# utf-8
# Python 3.6



DATA_PATH = "data/"

MODEL_BINARY_PATH = "models/binary"
PREPROC_BINARY_PATH = "preproc/binary"

MODEL_MULTY_PATH = "models/multy/"
PREPROC_MULTY_PATH = "preproc/multy/"



display_settings = {
    "max_columns": 500,
    "max_rows": 500,
    "max_colwidth": 500,
    "expand_frame_repr": True,
    "max_info_columns": 50,
    "width": 1000,
    "precision": 2,
    "show_dimensions": False
}

columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'serror_rate', 'srv_serror_rate', 'rerror_rate', 
    'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 
    'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]



protocol_type_dct = {5.0: 'tcp',
                     6.0: 'udp',
                     10.0: 'icmp'}

service_dct = {20.0: 'ssh', 
               80.0: 'http',
               447.0: 'ddm_dfm', 
               17.0: 'qotd', 
               55.0: 'isi_gl', 
               23.0: 'telnet', 
               43.0: 'whois',
               323.0: 'immp', 
               443.0: 'https'}

flag_dct = {1.0: 'S0',
            2.0: 'S1',
            3.0: 'SF',
            4.0: 'S2',
            5.0: 'S3',
            6.0: 'RSTO',
            7.0: 'RSTR',
            8.0: 'RSTOS0',
            9.0: 'RSTRH',
            10.0: 'SH',
            11.0: 'SHR',
            0.0: 'OTH',
            12.0: 'REJ'}

