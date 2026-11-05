r"""Extract only the victim server's captures (UCAP172.31.69.28 part 1 and 2) from the 21 Feb pcap.zip into
C:\datasets\cse-cic-ids2018\raw\Wednesday-21-02-2018\pcap\ (the archive's own folder name), streaming in chunks."""
import sys
import time
import zipfile
from pathlib import Path

ZIP = Path(r"C:\datasets\cse-cic-ids2018\raw\Wednesday-21-02-2018\pcap.zip")
OUT = ZIP.parent
z = zipfile.ZipFile(ZIP)
wanted = [i for i in z.infolist() if "UCAP172.31.69.28" in i.filename]
for info in wanted:
    dest = OUT / info.filename
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size == info.file_size:
        print(f"already there: {dest}", flush=True)
        continue
    t = time.perf_counter()
    done = 0
    with z.open(info) as src, open(dest, "wb") as dst:
        while True:
            chunk = src.read(64 * 1024 * 1024)
            if not chunk:
                break
            dst.write(chunk)
            done += len(chunk)
            if done % (2 * 1024 ** 3) < 64 * 1024 * 1024:
                print(f"  {info.filename}: {done / 1e9:.1f} of {info.file_size / 1e9:.1f} GB", flush=True)
    print(f"wrote {dest} ({dest.stat().st_size:,} bytes) in {time.perf_counter() - t:.0f} s", flush=True)
    with open(dest, "rb") as f:
        magic = f.read(4)
    kinds = {b"\xd4\xc3\xb2\xa1": "pcap (little-endian)", b"\xa1\xb2\xc3\xd4": "pcap (big-endian)",
             b"\x0a\x0d\x0d\x0a": "pcapng", b"\x4d\x3c\xb2\xa1": "pcap (nanosecond)"}
    print(f"  file type: {kinds.get(magic, 'unknown ' + magic.hex())}", flush=True)
print("UNPACK_DONE", flush=True)
