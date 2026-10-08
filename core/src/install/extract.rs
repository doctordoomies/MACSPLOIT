//! Safe extraction of a single reviewed executable member from a pinned archive.
//!
//! The archive's SHA-256 is already verified before this runs, but it is still
//! treated as hostile: only one **top-level, regular-file** entry whose name
//! exactly equals the expected member is ever written out. Path traversal,
//! absolute paths, symlinks, hardlinks, device/FIFO entries, duplicates, and
//! oversized (zip-bomb) members all fail closed. Nothing is extracted into the
//! final install directory — the caller passes a staging destination.

use super::manifest::ArchiveFormat;
use crate::error::{CoreError, Result};
use std::{
    io::{Read, Write},
    path::Path,
};

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

fn unsafe_archive(msg: &str) -> CoreError {
    CoreError::new("UnsafeArchive", msg)
}

/// Reject a member path that is absolute or escapes its root via `..`, a drive
/// prefix, or a leading `/`. Only plain relative paths are acceptable.
fn is_safe_relative(path: &Path) -> bool {
    use std::path::Component;
    if path.as_os_str().is_empty() {
        return false;
    }
    path.components().all(|c| matches!(c, Component::Normal(_)))
}

/// Stream `reader` into `dest`, enforcing a hard decompressed-size ceiling.
fn write_capped(reader: &mut dyn Read, dest: &Path, max: u64) -> Result<()> {
    let mut out = std::fs::File::create(dest)?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|e| CoreError::new("ArchiveError", &format!("Read error: {e}")))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > max {
            return Err(unsafe_archive("Archive member exceeds the allowed size."));
        }
        out.write_all(&buffer[..read])?;
    }
    out.flush()?;
    Ok(())
}

/// Extract exactly the expected `member` from `archive_path` to `dest`. On any
/// failure, `dest` is removed so no half-written executable survives.
pub fn extract_member(
    archive_path: &Path,
    format: ArchiveFormat,
    member: &str,
    dest: &Path,
    max_extracted: u64,
) -> Result<()> {
    // A member must be a single, normal path component (top-level, not nested).
    if member.is_empty() || Path::new(member).components().count() != 1 {
        return Err(unsafe_archive("Invalid expected member."));
    }
    let result = match format {
        ArchiveFormat::Zip => extract_zip(archive_path, member, dest, max_extracted),
        ArchiveFormat::TarGz => extract_tar_gz(archive_path, member, dest, max_extracted),
    };
    if result.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    result
}

fn extract_zip(archive_path: &Path, member: &str, dest: &Path, max: u64) -> Result<()> {
    let file = std::fs::File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| unsafe_archive(&format!("Malformed ZIP archive: {e}")))?;

    let mut member_index: Option<usize> = None;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|e| unsafe_archive(&format!("Malformed ZIP entry: {e}")))?;
        // Validate the archive's original filename before asking zip to produce
        // an enclosed path. Newer zip releases may normalize internal `..`
        // components when deriving an enclosed name; MACSPLOIT intentionally
        // rejects aliases such as `sub/../subfinder` instead of accepting a
        // normalized equivalent.
        if !is_safe_relative(Path::new(entry.name())) {
            return Err(unsafe_archive("ZIP entry has an unsafe path."));
        }
        // `enclosed_name` provides a second path-safety check for absolute,
        // traversal, platform-prefix, and malformed paths.
        let Some(name) = entry.enclosed_name() else {
            return Err(unsafe_archive("ZIP entry has an unsafe path."));
        };
        if !is_safe_relative(&name) {
            return Err(unsafe_archive("ZIP entry has an unsafe path."));
        }
        // Reject unsafe entry types anywhere in the archive (symlink/fifo/etc.).
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & S_IFMT;
            if kind != 0 && kind != S_IFREG && kind != S_IFDIR {
                return Err(unsafe_archive("ZIP contains a non-regular entry."));
            }
        }
        if name == Path::new(member) {
            if !entry.is_file() {
                return Err(unsafe_archive("Expected member is not a regular file."));
            }
            if member_index.is_some() {
                return Err(unsafe_archive("Archive contains a duplicate member."));
            }
            member_index = Some(index);
        }
    }
    let index =
        member_index.ok_or_else(|| unsafe_archive("Expected executable not found in archive."))?;
    let mut entry = archive
        .by_index(index)
        .map_err(|e| unsafe_archive(&format!("Malformed ZIP entry: {e}")))?;
    write_capped(&mut entry, dest, max)
}

fn extract_tar_gz(archive_path: &Path, member: &str, dest: &Path, max: u64) -> Result<()> {
    use tar::EntryType;
    let file = std::fs::File::open(archive_path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut extracted = false;
    let entries = archive
        .entries()
        .map_err(|e| unsafe_archive(&format!("Malformed tar archive: {e}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| unsafe_archive(&format!("Malformed tar entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| unsafe_archive(&format!("Unreadable tar entry path: {e}")))?
            .into_owned();
        if !is_safe_relative(&path) {
            return Err(unsafe_archive("tar entry has an unsafe path."));
        }
        match entry.header().entry_type() {
            EntryType::Regular | EntryType::Continuous => {}
            EntryType::Directory => continue, // benign
            EntryType::Symlink | EntryType::Link => {
                return Err(unsafe_archive("tar contains a symlink or hardlink."));
            }
            _ => return Err(unsafe_archive("tar contains a non-regular entry.")),
        }
        if path == Path::new(member) {
            if extracted {
                return Err(unsafe_archive("Archive contains a duplicate member."));
            }
            write_capped(&mut entry, dest, max)?;
            extracted = true;
        }
    }
    if !extracted {
        return Err(unsafe_archive("Expected executable not found in archive."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    // ---- ZIP fixtures -----------------------------------------------------

    fn zip_with<F: FnOnce(&mut zip::ZipWriter<std::fs::File>)>(
        dir: &Path,
        build: F,
    ) -> std::path::PathBuf {
        let path = dir.join("a.zip");
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        build(&mut writer);
        writer.finish().unwrap();
        path
    }

    fn opts() -> zip::write::FileOptions<'static, ()> {
        zip::write::FileOptions::default().unix_permissions(0o755)
    }

    // zip v8 normalizes names passed to ZipWriter, which makes it unsuitable for
    // constructing hostile path fixtures directly. Patch a same-length filename
    // in both the local and central directory records so the reader sees the raw
    // archive spelling an attacker could supply.
    fn patch_zip_entry_name(path: &Path, from: &[u8], to: &[u8]) {
        assert_eq!(from.len(), to.len());
        let mut bytes = std::fs::read(path).unwrap();
        let mut replacements = 0;
        for offset in 0..=bytes.len().saturating_sub(from.len()) {
            if &bytes[offset..offset + from.len()] == from {
                bytes[offset..offset + to.len()].copy_from_slice(to);
                replacements += 1;
            }
        }
        assert_eq!(replacements, 2, "expected local and central ZIP filenames");
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn zip_extracts_only_the_member_ignoring_junk() {
        let dir = tmp();
        let archive = zip_with(dir.path(), |w| {
            w.start_file("subfinder", opts()).unwrap();
            w.write_all(b"BINARY").unwrap();
            w.start_file("LICENSE.md", opts()).unwrap();
            w.write_all(b"license text").unwrap();
            w.start_file("README.md", opts()).unwrap();
            w.write_all(b"readme").unwrap();
        });
        let dest = dir.path().join("out");
        extract_member(&archive, ArchiveFormat::Zip, "subfinder", &dest, 1024).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"BINARY");
    }

    #[test]
    fn zip_rejects_traversal_and_absolute_paths() {
        let dir = tmp();
        let archive = zip_with(dir.path(), |w| {
            w.start_file("../evil", opts()).unwrap();
            w.write_all(b"x").unwrap();
        });
        let dest = dir.path().join("out");
        let err =
            extract_member(&archive, ArchiveFormat::Zip, "subfinder", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
        assert!(!dest.exists());

        let archive2 = zip_with(dir.path(), |w| {
            w.start_file("/etc/passwd", opts()).unwrap();
            w.write_all(b"x").unwrap();
        });
        let err2 =
            extract_member(&archive2, ArchiveFormat::Zip, "subfinder", &dest, 1024).unwrap_err();
        assert_eq!(err2.code, "UnsafeArchive");
    }

    #[test]
    fn zip_rejects_symlink_entry() {
        let dir = tmp();
        let archive = zip_with(dir.path(), |w| {
            w.add_symlink("subfinder", "/bin/sh", opts()).unwrap();
        });
        let dest = dir.path().join("out");
        let err =
            extract_member(&archive, ArchiveFormat::Zip, "subfinder", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
        assert!(!dest.exists());
    }

    #[test]
    fn zip_rejects_aliased_unsafe_paths() {
        let dir = tmp();
        // A hostile archive that smuggles a second `subfinder` entry under a
        // non-normal path (`./subfinder`). `enclosed_name` does not collapse it, so
        // our strict component check rejects the whole archive.
        let archive = zip_with(dir.path(), |w| {
            w.start_file("subfinder", opts()).unwrap();
            w.write_all(b"one").unwrap();
            w.start_file("./subfinder", opts()).unwrap();
            w.write_all(b"two").unwrap();
        });
        let dest = dir.path().join("out");
        let err =
            extract_member(&archive, ArchiveFormat::Zip, "subfinder", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
        assert!(!dest.exists());
    }

    #[test]
    fn zip_rejects_internal_dotdot_component() {
        let dir = tmp();
        let archive = zip_with(dir.path(), |w| {
            w.start_file("sub/aa/subfinder", opts()).unwrap();
            w.write_all(b"x").unwrap();
        });
        patch_zip_entry_name(&archive, b"sub/aa/subfinder", b"sub/../subfinder");

        let dest = dir.path().join("out");
        let err =
            extract_member(&archive, ArchiveFormat::Zip, "subfinder", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
        assert!(!dest.exists());
    }

    #[test]
    fn zip_rejects_wrong_name_and_nested_member() {
        let dir = tmp();
        let archive = zip_with(dir.path(), |w| {
            w.start_file("not-subfinder", opts()).unwrap();
            w.write_all(b"x").unwrap();
            w.start_file("nested/subfinder", opts()).unwrap();
            w.write_all(b"y").unwrap();
        });
        let dest = dir.path().join("out");
        let err =
            extract_member(&archive, ArchiveFormat::Zip, "subfinder", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn zip_rejects_oversized_member() {
        let dir = tmp();
        let archive = zip_with(dir.path(), |w| {
            w.start_file("subfinder", opts()).unwrap();
            w.write_all(&vec![0u8; 4096]).unwrap();
        });
        let dest = dir.path().join("out");
        let err =
            extract_member(&archive, ArchiveFormat::Zip, "subfinder", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
        assert!(!dest.exists());
    }

    #[test]
    fn malformed_zip_is_rejected() {
        let dir = tmp();
        let path = dir.path().join("bad.zip");
        std::fs::write(&path, b"this is not a zip file at all").unwrap();
        let dest = dir.path().join("out");
        let err = extract_member(&path, ArchiveFormat::Zip, "subfinder", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
    }

    // ---- TAR.GZ fixtures --------------------------------------------------

    fn targz_with<F: FnOnce(&mut tar::Builder<flate2::write::GzEncoder<std::fs::File>>)>(
        dir: &Path,
        build: F,
    ) -> std::path::PathBuf {
        let path = dir.join("a.tar.gz");
        let file = std::fs::File::create(&path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        build(&mut builder);
        builder.into_inner().unwrap().finish().unwrap();
        path
    }

    fn reg_header(size: u64, mode: u32) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_size(size);
        h.set_mode(mode);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        h
    }

    #[test]
    fn targz_extracts_only_the_member_ignoring_junk() {
        let dir = tmp();
        let archive = targz_with(dir.path(), |b| {
            let data = b"FFUFBIN";
            let mut h = reg_header(data.len() as u64, 0o755);
            b.append_data(&mut h, "ffuf", &data[..]).unwrap();
            let lic = b"license";
            let mut h2 = reg_header(lic.len() as u64, 0o644);
            b.append_data(&mut h2, "LICENSE", &lic[..]).unwrap();
        });
        let dest = dir.path().join("out");
        extract_member(&archive, ArchiveFormat::TarGz, "ffuf", &dest, 1024).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"FFUFBIN");
    }

    #[test]
    fn targz_rejects_symlink_and_hardlink() {
        let dir = tmp();
        let archive = targz_with(dir.path(), |b| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            b.append_link(&mut h, "ffuf", "/bin/sh").unwrap();
        });
        let dest = dir.path().join("out");
        let err = extract_member(&archive, ArchiveFormat::TarGz, "ffuf", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");

        let archive2 = targz_with(dir.path(), |b| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Link);
            h.set_size(0);
            h.set_mode(0o755);
            b.append_link(&mut h, "ffuf", "some-other-file").unwrap();
        });
        let err2 =
            extract_member(&archive2, ArchiveFormat::TarGz, "ffuf", &dest, 1024).unwrap_err();
        assert_eq!(err2.code, "UnsafeArchive");
    }

    #[test]
    fn targz_rejects_traversal_path() {
        let dir = tmp();
        // The tar writer sanitizes `..` paths, so inject the raw header name bytes
        // directly to simulate a hostile archive, then let our reader reject it.
        let archive = targz_with(dir.path(), |b| {
            let data = b"x";
            let mut h = reg_header(data.len() as u64, 0o755);
            {
                let old = h.as_old_mut();
                let name = b"../evil";
                old.name[..name.len()].copy_from_slice(name);
            }
            h.set_cksum();
            b.append(&h, &data[..]).unwrap();
        });
        let dest = dir.path().join("out");
        let err = extract_member(&archive, ArchiveFormat::TarGz, "ffuf", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
        assert!(!dest.exists());
    }

    #[test]
    fn targz_rejects_duplicate_member() {
        let dir = tmp();
        let archive = targz_with(dir.path(), |b| {
            let data = b"one";
            let mut h = reg_header(data.len() as u64, 0o755);
            b.append_data(&mut h, "ffuf", &data[..]).unwrap();
            let data2 = b"two";
            let mut h2 = reg_header(data2.len() as u64, 0o755);
            b.append_data(&mut h2, "ffuf", &data2[..]).unwrap();
        });
        let dest = dir.path().join("out");
        let err = extract_member(&archive, ArchiveFormat::TarGz, "ffuf", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
    }

    #[test]
    fn targz_member_not_found_when_wrong_name() {
        let dir = tmp();
        let archive = targz_with(dir.path(), |b| {
            let data = b"x";
            let mut h = reg_header(data.len() as u64, 0o755);
            b.append_data(&mut h, "not-ffuf", &data[..]).unwrap();
        });
        let dest = dir.path().join("out");
        let err = extract_member(&archive, ArchiveFormat::TarGz, "ffuf", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn targz_rejects_oversized_member() {
        let dir = tmp();
        let archive = targz_with(dir.path(), |b| {
            let data = vec![7u8; 4096];
            let mut h = reg_header(data.len() as u64, 0o755);
            b.append_data(&mut h, "ffuf", &data[..]).unwrap();
        });
        let dest = dir.path().join("out");
        let err = extract_member(&archive, ArchiveFormat::TarGz, "ffuf", &dest, 1024).unwrap_err();
        assert_eq!(err.code, "UnsafeArchive");
        assert!(!dest.exists());
    }

    #[test]
    fn is_safe_relative_semantics() {
        assert!(is_safe_relative(Path::new("ffuf")));
        assert!(is_safe_relative(Path::new("dir/ffuf")));
        assert!(!is_safe_relative(Path::new("../ffuf")));
        assert!(!is_safe_relative(Path::new("/abs/ffuf")));
        assert!(!is_safe_relative(Path::new("")));
    }

    #[test]
    fn written_member_is_a_regular_file() {
        // sanity: extraction produces a real file we can chmod +x
        let dir = tmp();
        let archive = zip_with(dir.path(), |w| {
            w.start_file("subfinder", opts()).unwrap();
            w.write_all(b"BIN").unwrap();
        });
        let dest = dir.path().join("out");
        extract_member(&archive, ArchiveFormat::Zip, "subfinder", &dest, 1024).unwrap();
        let meta = std::fs::symlink_metadata(&dest).unwrap();
        assert!(meta.file_type().is_file());
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}
