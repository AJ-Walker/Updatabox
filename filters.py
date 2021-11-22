import os
import mimetypes
import arrow


additional_file_types = {
    '.md': 'text/markdown'
}


def datetimeformat(date_str):
    dt = arrow.get(date_str)
    return dt.humanize()


def file_type(key):
    file_info = os.path.splitext(key)
    file_extension = file_info[1]
    try:
        return mimetypes.types_map[file_extension]
    except KeyError:
        filetype = 'Unknown'
        if(file_info[0].startswith('.') and file_extension == ''):
            filetype = 'text'
        if(file_extension == '.enc'):
            filetype = 'Encrypted File'
        if(file_extension in additional_file_types.keys()):
            filetype = additional_file_types[file_extension]

        return filetype

def file_size(byte_size):
    BASE_SIZE = 1024.00
    MEASURE = ["B", "KB", "MB", "GB", "TB", "PB"]

    def _fix_size(size, size_index):
        if not size:
            return "0"
        elif size_index == 0:
            return str(size)
        else:
            return "{:.2f}".format(size)

    current_size = byte_size
    size_index = 0

    while current_size >= BASE_SIZE and len(MEASURE) != size_index:
        current_size = current_size / BASE_SIZE
        size_index = size_index + 1

    size = _fix_size(current_size, size_index)
    measure = MEASURE[size_index]
    return size +' '+ measure


