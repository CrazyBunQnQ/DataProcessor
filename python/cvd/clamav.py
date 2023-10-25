import io
import tarfile


def cli_strtok(s, index, delimiter):
    """A simple string tokenizer based on the logic of cli_strtok."""
    tokens = s.split(delimiter)
    if index < len(tokens):
        return tokens[index]
    return None


def cl_cvdparse(header):
    """Parse the CVD header based on the logic of cl_cvdparse."""
    if not header.startswith("ClamAV-VDB:"):
        print("Not a CVD file")
        return None

    cvd = {}

    cvd['time'] = cli_strtok(header, 1, ":")
    cvd['version'] = int(cli_strtok(header, 2, ":"))
    cvd['signatures'] = int(cli_strtok(header, 3, ":"))
    cvd['func_level'] = int(cli_strtok(header, 4, ":"))
    cvd['md5'] = cli_strtok(header, 5, ":")
    cvd['digital_signature'] = cli_strtok(header, 6, ":")
    cvd['builder'] = cli_strtok(header, 7, ":")
    cvd['stime'] = int(cli_strtok(header, 8, ":"))

    return cvd


def cl_cvdhead(file_path):
    """Read and parse the CVD header based on the logic of cl_cvdhead."""
    with open(file_path, "rb") as f:
        header = f.read(512).decode(errors='ignore')
    return cl_cvdparse(header)


def cli_untgz(file_obj, destdir):
    try:
        # Create a tarfile object using the uncompressed data
        with tarfile.open(fileobj=file_obj, mode='r:gz') as tf:
            # Extract each member from the tarfile
            for member in tf.getmembers():
                # Check if the member is a directory or unknown type
                if member.isdir():
                    print("cli_untgz_py_v2: Directories are not supported in CVD")
                    return -1

                # Check for slash in filename, which is not allowed
                if '/' in member.name:
                    print("cli_untgz_py_v2: Slash separators are not allowed in CVD")
                    return -1

                # Extract the member to the destination directory
                tf.extract(member, path=destdir)

        return 0
    except Exception as e:
        print(f"cli_untgz_py_v2: Error - {e}")
        return -1


def cli_cvdunpack(file, dir):
    try:
        # Open the file
        with open(file, 'rb') as f:
            # Skip the header (512 bytes)
            f.seek(512)

            # Create a new file object from the remaining bytes
            file_data = f.read()
            file_obj = io.BytesIO(file_data)

            # Pass the new file object to the modified cli_untgz_py function
            ret = cli_untgz(file_obj, dir)
            return ret
    except Exception as e:
        print(f"cli_cvdunpack_py_v3: Error - {e}")
        return -1


cvd_header = cl_cvdhead("F:\数据库备份\ClamAV\daily.cvd")
cvd_header
result_cvdunpack_daily = cli_cvdunpack("F:\数据库备份\ClamAV\daily.cvd", "F:\数据库备份\ClamAV\daily")

cvd_header = cl_cvdhead("F:\数据库备份\ClamAV\\bytecode.cvd")
cvd_header
result_cvdunpack_daily = cli_cvdunpack("F:\数据库备份\ClamAV\\bytecode.cvd", "F:\数据库备份\ClamAV\\bytecode")

cvd_header = cl_cvdhead("F:\数据库备份\ClamAV\main.cvd")
result_cvdunpack_daily = cli_cvdunpack("F:\数据库备份\ClamAV\main.cvd", "F:\数据库备份\ClamAV\main")
