use anyhow::{Context, Result};
use log::{info, warn};
use std::ffi::CString;
use std::fs::{Permissions, set_permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::module::{handle_updated_modules, prune_modules};
use crate::{assets, defs, init_event, metamodule, restorecon, utils};

fn lookup_manager_uid() -> Option<u32> {
    if let Ok(s) = std::fs::read_to_string("/data/data/org.lsposed.lspromise/manager.uid") {
        if let Ok(u) = s.trim().parse::<u32>() {
            return Some(u);
        }
    }
    if let Ok(st) = rustix::fs::stat("/data/data/me.weishu.kernelsu") {
        return Some(st.st_uid % 100_000);
    }
    None
}

fn recrown_manager() {
    // track_throne at module-init often misses the manager on Samsung.
    // The packages.list watcher re-runs the scan on CREATE/MOVE of that file.
    let src = Path::new("/data/system/packages.list");
    let tmp = Path::new("/data/system/packages.list.ksu-nudge");
    match std::fs::copy(src, tmp) {
        Ok(_) => {
            if let Err(e) = std::fs::rename(tmp, src) {
                warn!("recrown rename failed: {e:#}");
                let _ = std::fs::remove_file(tmp);
            } else {
                info!("retried manager crown via packages.list nudge");
            }
        }
        Err(e) => warn!("recrown copy failed: {e:#}"),
    }
}

fn mark_ready() {
    let body = b"ok\n";
    for p in [
        "/data/data/org.lsposed.lspromise/ksu-ready",
        "/data/local/tmp/lspromise-ksu-ready",
    ] {
        match std::fs::write(p, body) {
            Ok(_) => {
                let _ = set_permissions(p, Permissions::from_mode(0o644));
                info!("ready marker {p}");
            }
            Err(e) => warn!("ready marker {p}: {e:#}"),
        }
    }
}

fn dump_process_info(label: &str) {
    use rustix::process::{getgid, getgroups, getpid, getuid};

    let pid = getpid().as_raw_nonzero();
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    let groups: Vec<String> = getgroups()
        .unwrap_or_default()
        .iter()
        .map(|g| g.as_raw().to_string())
        .collect();
    let selinux = std::fs::read_to_string("/proc/self/attr/current")
        .unwrap_or_else(|_| "unknown".to_string());
    let seccomp = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Seccomp:"))
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    info!(
        "[{label}] pid={pid}, uid={uid}, gid={gid}, groups=[{}], selinux={}, {seccomp}",
        groups.join(","),
        selinux.trim(),
    );
}

pub fn run(_package_name: &String, kmi: Option<String>, allow_shell: bool) -> Result<()> {
    info!("late-load command triggered!");
    dump_process_info("late-load start");

    // Load the LKM before touching /data/adb. On Samsung we are exec'd via a
    // bind-mount over /system/bin/logcat, so DEFEX sees an immutable-root
    // task and denies /data/adb/ksud until kernelsu.ko installs its
    // task_defex_enforce bypass and escape_to_root_for_init() puts us in
    // the ksu domain.
    if ksuinit::has_kernelsu() {
        info!("KernelSU already loaded, skip loading ko");
    } else {
        let kmi = kmi.map_or_else(
            || crate::boot_patch::get_current_kmi().context("Failed to detect current KMI version"),
            Ok,
        )?;
        info!("Detected KMI: {kmi}");

        let ko_name = format!("{kmi}_kernelsu.ko");
        let ko_data = assets::get_asset_data(&ko_name)
            .with_context(|| format!("Failed to get {ko_name} from assets"))?;

        info!("Loading kernelsu.ko for KMI {kmi}...");
        let mut param = String::new();
        if allow_shell {
            param.push_str("allow_shell=1");
        }
        if let Some(uid) = lookup_manager_uid() {
            if !param.is_empty() {
                param.push(' ');
            }
            param.push_str(&format!("manager_uid={uid}"));
            info!("loading with manager_uid={uid}");
        }
        let cparams = CString::new(param).unwrap_or_else(|_| CString::new("").unwrap());
        ksuinit::load_module(&ko_data, &cparams).context("Failed to load kernelsu.ko")?;
        info!("kernelsu.ko loaded successfully!");
        dump_process_info("after load_module");
    }

    utils::stage_daemon_from("/data/local/tmp/.ksud-stage").context("Failed to stage ksud")?;

    // We need to reset stdin/stdout/stderr; otherwise, sending file descriptors via cmd transactions
    // will be blocked by SELinux because its fsec->sid is still u:r:su:s0 instead of u:r:ksu:s0.
    utils::reset_std()?;

    utils::umask(0);

    if let Err(e) = crate::module_config::clear_all_temp_configs() {
        warn!("clear temp configs failed: {e}");
    }

    // finish_install extracts assets into /data/adb/ksu/bin and restorecons
    // them. The module re-enabled SELinux enforcing during its init, and on
    // Samsung the ksu domain hits EPERM writing those under enforcing. We are
    // uid 0 in the ksu domain here, so drop to permissive for the install and
    // restore after (matches the permissive window the exploit ran under).
    let was_enforcing = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    if was_enforcing {
        if let Err(e) = std::fs::write("/sys/fs/selinux/enforce", "0") {
            warn!("could not drop SELinux to permissive for install: {e}");
        }
    }
    let install_result = utils::finish_install(None).context("Failed to finish ksud installation");
    if was_enforcing {
        let _ = std::fs::write("/sys/fs/selinux/enforce", "1");
    }
    // LKM is already live. A failed userspace install must not abort the
    // late-load — Pixel's 100% path still crowns the manager from here.
    if let Err(e) = install_result {
        warn!("finish_install failed (module is loaded): {e:#}");
    }

    recrown_manager();
    if let Some(uid) = lookup_manager_uid() {
        let p = "/sys/module/kernelsu/parameters/manager_uid";
        match std::fs::write(p, uid.to_string()) {
            Ok(_) => info!("set manager_uid {uid}"),
            Err(e) => warn!("set manager_uid {uid}: {e:#}"),
        }
    } else {
        warn!("could not resolve manager uid");
    }
    mark_ready();

    // 5. Handle module updates
    if let Err(e) = handle_updated_modules() {
        warn!("handle updated modules failed: {e}");
    }

    if let Err(e) = prune_modules() {
        warn!("prune modules failed: {e}");
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {e}");
    }

    // 6. Load SELinux rules
    if crate::module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }

    if let Err(e) = crate::profile::apply_sepolies() {
        warn!("apply root profile sepolicy failed: {e}");
    }

    // 7. Initialize features
    if let Err(e) = crate::feature::init_features() {
        warn!("init features failed: {e}");
    }

    // 8. Execute late-load stage scripts (blocking)
    init_event::run_stage("late-load", true);

    // 9. Load system.prop
    if let Err(e) = crate::module::load_system_prop() {
        warn!("load system.prop failed: {e}");
    }

    // 10. Execute metamodule mount script (OverlayFS)
    if let Err(e) = metamodule::exec_mount_script(defs::MODULE_DIR) {
        warn!("execute metamodule mount failed: {e}");
    }

    // 11. Execute post-mount stage scripts (blocking)
    init_event::run_stage("post-mount", true);

    // 12. Execute service stage scripts (non-blocking)
    init_event::run_stage("service", false);

    // 13. Execute boot-completed stage scripts (non-blocking)
    init_event::run_stage("boot-completed", false);

    Ok(())
}
