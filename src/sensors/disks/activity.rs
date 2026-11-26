use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

// Diskstats reports 512-byte sectors regardless of the device's sector size.
const SECTOR_BYTES: u64 = 512;
type Device = (u32, u32);
type CountersByDevice = HashMap<Device, Option<DiskCounters>>;

#[derive(Debug)]
struct DiskCounters {
    name: Vec<u8>,
    read: u64,
    written: u64,
}

#[derive(Debug)]
struct SyntheticDevice {
    kind: Vec<u8>,
    source: Vec<u8>,
    backing: Device,
}

#[derive(Debug, Default)]
pub(super) struct DiskActivity {
    previous: HashMap<Device, DiskCounters>,
    synthetic_devices: HashMap<Device, SyntheticDevice>,
}

impl DiskActivity {
    pub(super) fn sample(&mut self) -> (u64, u64) {
        let Ok(mounts) = fs::read("/proc/self/mountinfo") else {
            self.previous.clear();
            return (0, 0);
        };
        let stats = fs::read("/proc/diskstats").unwrap_or_default();
        self.record(&mounts, &stats)
    }

    fn record(&mut self, mounts: &[u8], stats: &[u8]) -> (u64, u64) {
        self.record_with_source(mounts, stats, source_device)
    }

    fn record_with_source(
        &mut self,
        mounts: &[u8],
        stats: &[u8],
        resolve_source: impl Fn(&[u8], &CountersByDevice, bool) -> Option<Device>,
    ) -> (u64, u64) {
        let mut counters = HashMap::new();
        for (device, counter) in lines(stats).filter_map(disk_counters) {
            counters
                .entry(device)
                .and_modify(|counter| *counter = None)
                .or_insert(Some(counter));
        }

        let mut mounted = HashSet::new();
        let mut synthetic_devices = HashMap::new();
        for (device, kind, source) in lines(mounts).filter_map(mounted_device) {
            // Bind mounts can share a device number. Major zero marks an anonymous device.
            if device.0 != 0 {
                mounted.insert(device);
                continue;
            }

            // Userspace FUSE filesystems can set their own source string.
            let require_block_device = kind == b"fuse" || kind.starts_with(b"fuse.");
            if !require_block_device && !matches!(kind, b"btrfs" | b"bcachefs" | b"fuseblk") {
                continue;
            }
            // A symlink can move while mountinfo continues to name the same source.
            let backing = synthetic_devices
                .get(&device)
                .or_else(|| self.synthetic_devices.get(&device))
                .filter(|mount| mount.kind == kind && mount.source == source)
                .map(|mount| mount.backing)
                .or_else(|| resolve_source(source, &counters, require_block_device));
            if let Some(backing) = backing {
                synthetic_devices.insert(
                    device,
                    SyntheticDevice {
                        kind: kind.to_vec(),
                        source: source.to_vec(),
                        backing,
                    },
                );
                mounted.insert(backing);
            }
        }

        let mut current = HashMap::new();
        let (mut read, mut written) = (0_u64, 0_u64);
        for device in mounted {
            // Missing and ambiguous rows have no baseline.
            let Some(Some(counter)) = counters.remove(&device) else {
                continue;
            };
            if let Some(previous) = self
                .previous
                .get(&device)
                .filter(|p| p.name == counter.name)
            {
                read = read.saturating_add(counter.read.saturating_sub(previous.read));
                written = written.saturating_add(counter.written.saturating_sub(previous.written));
            }
            current.insert(device, counter);
        }
        self.previous = current;
        self.synthetic_devices = synthetic_devices;
        (read, written)
    }
}

fn lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|&byte| byte == b'\n')
}

fn fields(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    line.split(|&byte| matches!(byte, b' ' | b'\t'))
        .filter(|field| !field.is_empty())
}

fn number<T: FromStr>(field: &[u8]) -> Option<T> {
    std::str::from_utf8(field).ok()?.parse().ok()
}

fn disk_counters(line: &[u8]) -> Option<(Device, DiskCounters)> {
    let mut fields = fields(line);
    let device = (number(fields.next()?)?, number(fields.next()?)?);
    let name = fields.next()?;
    // Sectors read and written are the third and seventh I/O fields after the name.
    let read = number::<u64>(fields.nth(2)?)?.checked_mul(SECTOR_BYTES)?;
    let written = number::<u64>(fields.nth(3)?)?.checked_mul(SECTOR_BYTES)?;
    Some((
        device,
        DiskCounters {
            name: name.to_vec(),
            read,
            written,
        },
    ))
}

fn mounted_device(line: &[u8]) -> Option<(Device, &[u8], &[u8])> {
    let mut fields = fields(line);
    let mut device_fields = fields.nth(2)?.split(|&byte| byte == b':');
    let device = (
        number(device_fields.next()?)?,
        number(device_fields.next()?)?,
    );
    if device_fields.next().is_some() {
        return None;
    }
    let mount = fields.nth(1)?;
    if mount.starts_with(b"/sys")
        || mount.starts_with(b"/proc")
        || (mount.starts_with(b"/run") && !mount.starts_with(b"/run/media"))
    {
        return None;
    }
    fields.find(|&field| field == b"-")?;
    let kind = fields.next()?;
    let source = fields.next()?;
    // Keep the disk widget's existing exclusions for optical and image mounts.
    (!matches!(kind, b"iso9660" | b"squashfs")).then_some((device, kind, source))
}

fn source_device(
    source: &[u8],
    counters: &CountersByDevice,
    require_block_device: bool,
) -> Option<Device> {
    source_device_with(
        source,
        counters,
        require_block_device,
        DevicePathMetadata::read,
        |path| path.canonicalize().ok(),
    )
}

#[derive(Clone, Copy, Debug)]
struct DevicePathMetadata {
    uid: u32,
    mode: u32,
    is_dir: bool,
    block_rdev: Option<u64>,
}

impl DevicePathMetadata {
    fn read(path: &Path) -> Option<Self> {
        let metadata = fs::symlink_metadata(path).ok()?;
        let file_type = metadata.file_type();
        Some(Self {
            uid: metadata.uid(),
            mode: metadata.mode(),
            is_dir: file_type.is_dir(),
            block_rdev: file_type.is_block_device().then_some(metadata.rdev()),
        })
    }
}

fn source_device_with(
    source: &[u8],
    counters: &CountersByDevice,
    require_block_device: bool,
    metadata: impl Fn(&Path) -> Option<DevicePathMetadata>,
    canonicalize: impl Fn(&Path) -> Option<PathBuf>,
) -> Option<Device> {
    let source = unescape_mount_source(source)?;
    let name = source.strip_prefix(b"/dev/")?;
    let by_name = |name: &[u8]| {
        let mut matches = counters
            .iter()
            .filter_map(|(&device, counter)| (counter.as_ref()?.name == name).then_some(device));
        let device = matches.next()?;
        matches.next().is_none().then_some(device)
    };
    if !require_block_device && let Some(device) = by_name(name) {
        return Some(device);
    }

    if name
        .split(|&byte| byte == b'/')
        .any(|part| matches!(part, b"" | b"." | b".."))
    {
        return None;
    }
    let source = Path::new(OsStr::from_bytes(&source));
    // Resolve aliases only through system-owned device directories, including LVM and mdraid.
    // The Flatpak user namespace may map the system's owner to a nonzero uid.
    let dev_owner = metadata(Path::new("/dev"))?.uid;
    let parents: Vec<_> = source
        .ancestors()
        .skip(1)
        .take_while(|p| *p != Path::new("/"))
        .collect();
    for parent in parents.into_iter().rev() {
        let directory = metadata(parent)?;
        if !directory.is_dir || directory.uid != dev_owner || directory.mode & 0o022 != 0 {
            return None;
        }
    }
    let resolved = canonicalize(source)?;
    let name = resolved.strip_prefix("/dev/").ok()?;
    if require_block_device {
        return device_number(metadata(&resolved)?.block_rdev?);
    }
    by_name(name.as_os_str().as_bytes())
}

fn device_number(encoded: u64) -> Option<Device> {
    // Linux st_rdev uses the device number encoding exposed by major() and minor().
    let major = ((encoded >> 8) & 0xfff) | ((encoded >> 32) & 0xffff_f000);
    let minor = (encoded & 0xff) | ((encoded >> 12) & 0xffff_ff00);
    Some((major.try_into().ok()?, minor.try_into().ok()?))
}

fn unescape_mount_source(mut source: &[u8]) -> Option<Cow<'_, [u8]>> {
    if !source.contains(&b'\\') {
        return Some(Cow::Borrowed(source));
    }
    let mut decoded = Vec::with_capacity(source.len());
    while let Some((&byte, rest)) = source.split_first() {
        source = rest;
        if byte == b'\\' {
            decoded.push(match source.get(..3)? {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return None,
            });
            source = &source[3..];
        } else {
            decoded.push(byte);
        }
    }
    Some(Cow::Owned(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTS: &[u8] = b"1 0 252:10 / / rw - ext4 /dev/alias rw\n\
        2 0 252:11 / /mnt rw - ext4 /dev/dm-11 rw\n";

    fn stats(first: (u64, u64), second: (u64, u64)) -> String {
        format!(
            "252 10 dm-10 0 0 {} 0 0 0 {}\n252 11 dm-11 0 0 {} 0 0 0 {}\n",
            first.0, first.1, second.0, second.1
        )
    }

    #[test]
    fn counts_each_mounted_device_once() {
        let mut activity = DiskActivity::default();
        let mounts = [
            MOUNTS,
            b"3 1 252:10 /dir /alias rw shared:7 - ext4 /dev/dm-10 rw\n",
            b"3 1 252:10 /dir /alias rw shared:7 - ext4 /dev/dm-10 rw\n",
        ]
        .concat();
        // Two distinct devices must both count even when their counters are identical.
        assert_eq!(
            activity.record(&mounts, stats((10, 20), (10, 20)).as_bytes()),
            (0, 0)
        );
        let next = stats((11, 23), (11, 23)) + "252 12 dm-12 0 0 100 0 0 0 100\n";
        assert_eq!(activity.record(&mounts, next.as_bytes()), (1024, 3072));
    }

    #[test]
    fn mount_identity_wins_when_the_source_names_another_device() {
        let mut activity = DiskActivity::default();
        activity.record(MOUNTS, stats((1000, 1000), (10, 10)).as_bytes());
        let retargeted = b"1 0 252:10 / / rw - ext4 /dev/dm-11 rw\n\
            2 0 252:11 / /mnt rw - ext4 /dev/dm-11 rw\n";
        assert_eq!(
            activity.record(retargeted, stats((1001, 1001), (11, 11)).as_bytes()),
            (1024, 1024)
        );
    }

    #[test]
    fn missing_or_initially_unavailable_counters_establish_a_new_baseline() {
        for initial in [
            stats((1000, 1000), (10, 10)),
            String::from("252 11 dm-11 0 0 10 0 0 0 10\n"),
        ] {
            let mut activity = DiskActivity::default();
            assert_eq!(activity.record(MOUNTS, initial.as_bytes()), (0, 0));
            assert_eq!(
                activity.record(MOUNTS, b"252 11 dm-11 0 0 11 0 0 0 11\n"),
                (512, 512)
            );
            assert_eq!(
                activity.record(MOUNTS, stats((2000, 2000), (12, 12)).as_bytes()),
                (512, 512)
            );
            assert_eq!(
                activity.record(MOUNTS, stats((2001, 2001), (13, 13)).as_bytes()),
                (1024, 1024)
            );
        }
    }

    #[test]
    fn newly_visible_mounts_seed_the_counter_only_once() {
        let mut activity = DiskActivity::default();
        let one = b"1 0 252:10 / / rw - ext4 /dev/dm-10 rw\n";
        activity.record(one, stats((100, 100), (200, 200)).as_bytes());
        assert_eq!(
            activity.record(MOUNTS, stats((101, 102), (299, 299)).as_bytes()),
            (512, 1024)
        );
        let aliases = [MOUNTS, b"3 0 252:10 / /alias rw - ext4 /dev/dm-10 rw\n"].concat();
        assert_eq!(
            activity.record(&aliases, stats((102, 103), (300, 300)).as_bytes()),
            (1024, 1024)
        );
        assert_eq!(
            activity.record(&[], stats((111, 112), (310, 310)).as_bytes()),
            (0, 0)
        );
        assert_eq!(
            activity.record(MOUNTS, stats((130, 140), (320, 320)).as_bytes()),
            (0, 0)
        );
    }

    #[test]
    fn handles_unchanged_counters_backwards_counters_and_name_changes() {
        let mut activity = DiskActivity::default();
        let initial = stats((100, 100), (200, 200));
        activity.record(MOUNTS, initial.as_bytes());
        assert_eq!(activity.record(MOUNTS, initial.as_bytes()), (0, 0));
        assert_eq!(
            activity.record(MOUNTS, stats((1, 102), (199, 200)).as_bytes()),
            (0, 1024)
        );
        assert_eq!(
            activity.record(MOUNTS, stats((2, 103), (200, 201)).as_bytes()),
            (1024, 1024)
        );
        let renamed = stats((100, 200), (201, 202)).replace("dm-10", "dm-20");
        assert_eq!(activity.record(MOUNTS, renamed.as_bytes()), (512, 512));
    }

    #[test]
    fn filters_system_optical_and_image_mounts_but_keeps_removable_storage() {
        let mut activity = DiskActivity::default();
        let mounts = b"1 0 252:10 / /sys rw - ext4 /dev/dm-10 rw\n\
            2 0 252:10 / /proc2 rw - ext4 /dev/dm-10 rw\n\
            3 0 252:10 / /run/private rw - ext4 /dev/dm-10 rw\n\
            4 0 252:10 / /opt rw - squashfs /dev/dm-10 rw\n\
            5 0 252:10 / /media/dvd rw - iso9660 /dev/dm-10 rw\n\
            6 0 252:11 / /run/media/name/disk\\0401 rw - ext4 /dev/dm-11 rw\n";
        activity.record(mounts, stats((10, 10), (10, 10)).as_bytes());
        assert_eq!(
            activity.record(mounts, stats((110, 110), (11, 12)).as_bytes()),
            (512, 1024)
        );
    }

    #[test]
    fn synthetic_mount_ids_fall_back_only_for_block_backed_filesystems() {
        let mut activity = DiskActivity::default();
        let mounts = b"1 0 0:21 /subvolume /mnt/one rw - btrfs /dev/dm-10 rw\n\
            2 0 0:22 /other /mnt/two rw - btrfs /dev/dm-10 rw\n\
            3 0 0:23 / /mnt/ignored rw - tmpfs /dev/dm-11 rw\n\
            4 0 0:24 / /mnt/fuse rw - fuse.test /dev/null rw\n\
            5 0 0:25 / /mnt/bad rw - btrfs /dev/../dm-11 rw\n";
        let initial = stats((10, 10), (10, 10)) + "1 3 null 0 0 100 0 0 0 200\n";
        activity.record(mounts, initial.as_bytes());
        let next = stats((11, 12), (100, 100)) + "1 3 null 0 0 200 0 0 0 400\n";
        assert_eq!(activity.record(mounts, next.as_bytes()), (512, 1024));
    }

    #[test]
    fn fuse_mounts_use_the_block_node_number_when_its_name_matches_another_device() {
        let metadata = |path: &Path| match path.to_str()? {
            "/dev" | "/dev/disk" => Some(DevicePathMetadata {
                uid: 100_000,
                mode: 0o755,
                is_dir: true,
                block_rdev: None,
            }),
            // The visible basename belongs to 252:11 in diskstats. The node is 252:10.
            "/dev/dm-11" => Some(DevicePathMetadata {
                uid: 100_000,
                mode: 0o660,
                is_dir: false,
                block_rdev: Some(0xfc0a),
            }),
            _ => None,
        };
        for kind in [
            "fuse",
            "fuse.dislocker",
            "fuse.ext2",
            "fuse.ext3",
            "fuse.ext4",
        ] {
            let mounts = format!("1 0 0:21 / /mnt rw - {kind} /dev/disk/alias rw\n");
            let resolve = |source: &[u8], counters: &CountersByDevice, require_block_device| {
                source_device_with(source, counters, require_block_device, metadata, |path| {
                    (path == Path::new("/dev/disk/alias")).then(|| PathBuf::from("/dev/dm-11"))
                })
            };
            let mut activity = DiskActivity::default();
            activity.record_with_source(
                mounts.as_bytes(),
                stats((10, 20), (100, 200)).as_bytes(),
                resolve,
            );
            assert_eq!(
                activity.record_with_source(
                    mounts.as_bytes(),
                    stats((11, 22), (180, 500)).as_bytes(),
                    resolve,
                ),
                (512, 1024),
                "{kind}"
            );
        }
    }

    #[test]
    fn device_alias_rejects_unsafe_parent_directories() {
        let directory = DevicePathMetadata {
            uid: 100_000,
            mode: 0o755,
            is_dir: true,
            block_rdev: None,
        };
        let counters = HashMap::from([(
            (252, 10),
            Some(DiskCounters {
                name: b"dm-10".to_vec(),
                read: 0,
                written: 0,
            }),
        )]);
        for (parent, expected) in [
            (directory, Some((252, 10))),
            (
                DevicePathMetadata {
                    uid: 1000,
                    ..directory
                },
                None,
            ),
            (
                DevicePathMetadata {
                    mode: 0o775,
                    ..directory
                },
                None,
            ),
            (
                DevicePathMetadata {
                    mode: 0o757,
                    ..directory
                },
                None,
            ),
            (
                DevicePathMetadata {
                    is_dir: false,
                    ..directory
                },
                None,
            ),
        ] {
            let device = source_device_with(
                b"/dev/disk/by-id/alias",
                &counters,
                false,
                |path| match path.to_str()? {
                    "/dev" | "/dev/disk/by-id" => Some(directory),
                    "/dev/disk" => Some(parent),
                    _ => None,
                },
                |path| {
                    assert_eq!(path, Path::new("/dev/disk/by-id/alias"));
                    Some(PathBuf::from("/dev/dm-10"))
                },
            );
            assert_eq!(device, expected, "{parent:?}");
        }
    }

    #[test]
    fn device_number_preserves_extended_major_and_minor_bits() {
        assert_eq!(device_number(0x0001_0301), Some((259, 1)));
        assert_eq!(
            device_number(0x0001_2000_6783_459a),
            Some((0x0001_2345, 0x0006_789a))
        );
    }

    #[test]
    fn a_synthetic_mount_keeps_its_backing_until_unmounted() {
        let mut activity = DiskActivity::default();
        let original = b"1 0 0:21 /subvolume /mnt/one rw - btrfs /dev/vg/current rw\n";
        let alias_mount = b"2 0 0:21 /subvolume /mnt/alias rw - btrfs /dev/vg/current rw\n";
        let remounted = b"3 0 0:21 /subvolume /mnt/one rw - btrfs /dev/vg/current rw\n";
        let initial_source = |_: &[u8], _: &CountersByDevice, _| Some((252, 10));
        let retargeted_source = |_: &[u8], _: &CountersByDevice, _| Some((252, 11));
        activity.record_with_source(
            original,
            stats((100, 100), (20, 20)).as_bytes(),
            initial_source,
        );
        // The existing mount stays bound to its original device after the alias moves.
        assert_eq!(
            activity.record_with_source(
                alias_mount,
                stats((101, 102), (110, 110)).as_bytes(),
                retargeted_source
            ),
            (512, 1024)
        );
        assert_eq!(
            activity.record_with_source(
                alias_mount,
                b"252 11 dm-11 0 0 111 0 0 0 111\n",
                retargeted_source
            ),
            (0, 0)
        );
        assert_eq!(
            activity.record_with_source(
                alias_mount,
                stats((400, 400), (112, 112)).as_bytes(),
                retargeted_source
            ),
            (0, 0)
        );
        assert_eq!(
            activity.record_with_source(
                alias_mount,
                stats((401, 402), (113, 113)).as_bytes(),
                retargeted_source
            ),
            (512, 1024)
        );
        activity.record(b"", stats((401, 402), (113, 113)).as_bytes());
        // The mount disappeared, so reusing its synthetic ID needs a fresh baseline.
        assert_eq!(
            activity.record_with_source(
                remounted,
                stats((401, 402), (200, 200)).as_bytes(),
                retargeted_source
            ),
            (0, 0)
        );
        assert_eq!(
            activity.record_with_source(
                remounted,
                stats((900, 900), (203, 204)).as_bytes(),
                retargeted_source
            ),
            (1536, 2048)
        );
    }

    #[test]
    fn a_changed_mount_source_is_resolved_again() {
        let mut activity = DiskActivity::default();
        let original = b"1 0 0:21 / /mnt rw - btrfs /dev/dm-10 rw\n";
        let replacement = b"1 0 0:21 / /mnt rw - btrfs /dev/dm-11 rw\n";
        activity.record(original, stats((100, 100), (20, 20)).as_bytes());
        assert_eq!(
            activity.record(replacement, stats((120, 120), (100, 100)).as_bytes()),
            (0, 0)
        );
        assert_eq!(
            activity.record(replacement, stats((150, 150), (101, 102)).as_bytes()),
            (512, 1024)
        );
    }

    #[test]
    fn mount_paths_can_contain_non_utf8_bytes_and_carriage_returns() {
        let mut activity = DiskActivity::default();
        let mounts = b"1 0 252:10 / /mnt/nonutf8\xff\r rw - ext4 /dev/dm-10 rw\n";
        activity.record(mounts, stats((100, 200), (50, 60)).as_bytes());
        assert_eq!(
            activity.record(mounts, stats((103, 204), (51, 61)).as_bytes()),
            (1536, 2048)
        );
    }

    #[test]
    fn decodes_proc_path_escapes_and_rejects_invalid_escapes() {
        assert_eq!(
            unescape_mount_source(br"/dev/a\040b\134c\011d\012e").as_deref(),
            Some(b"/dev/a b\\c\td\ne".as_slice())
        );
        assert!(unescape_mount_source(br"/dev/a\000b").is_none());
        assert!(unescape_mount_source(br"/dev/a\40").is_none());
    }

    #[test]
    fn malformed_overflowing_and_ambiguous_rows_cannot_seed_a_baseline() {
        let mut activity = DiskActivity::default();
        let mounts = [
            b"bad mount row\n".as_slice(),
            b"1 0 252:10 / /mnt/nonutf8\xff rw - ext4 /dev/dm-10 rw\n",
            MOUNTS,
        ]
        .concat();
        let bad = b"252 10 dm-10 0 0 18446744073709551615 0 0 0 100\n\
            252 10 incomplete\n0 0 malformed 0 0 nope 0 0 0 0\n\
            252 11 dm-11 0 0 10 0 0 0 10\n252 11 again 0 0 11 0 0 0 11\n";
        assert_eq!(activity.record(&mounts, bad), (0, 0));
        assert_eq!(
            activity.record(&mounts, stats((100, 100), (200, 200)).as_bytes()),
            (0, 0)
        );
        assert_eq!(
            activity.record(&mounts, stats((101, 101), (201, 201)).as_bytes()),
            (1024, 1024)
        );
    }

    #[test]
    fn aggregate_overflow_saturates() {
        let mut activity = DiskActivity::default();
        activity.record(MOUNTS, stats((0, 0), (0, 0)).as_bytes());
        let max_sectors = u64::MAX / SECTOR_BYTES;
        assert_eq!(
            activity.record(MOUNTS, stats((max_sectors, max_sectors), (1, 1)).as_bytes()),
            (u64::MAX, u64::MAX)
        );
    }
}
