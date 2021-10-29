# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    result_types = {
        'start': {
            'format': 'Start'
        },
        'address': {
            'format': '{{data.description}}'
        },
        'data': {
            'format': '{{data.description}}'
        },
        'stop': {
            'format': 'Stop'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.
        '''
        self.type_history = ''
        self.type_now = ''
        self.data_print_len = 16
        self.data_len = 0

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.
        '''
        self.type_history = self.type_now
        self.type_now = frame.type
        if frame.type == "start":
            print('Start')
            return AnalyzerFrame('start', frame.start_time, frame.end_time, {
            })
        elif frame.type == "address":
            str_direction = 'Read' if frame.data['read'] else 'Write'
            int_address = (frame.data['address'][0] << 1 ) | (1 if frame.data['read'] else 0)
            bytes_address = int_address.to_bytes(length=1,byteorder='big',signed=False)
            str_ack = 'ACK' if frame.data['ack'] else 'NAK'
            if frame.data['read']:
                print('Read: %X'%int_address,'+ ' + str_ack)
            else:
                print('Write: %X'%int_address,'+ ' + str_ack)
            return AnalyzerFrame('address', frame.start_time, frame.end_time, {
                'ack': frame.data['ack'],
                'address': bytes_address,
                'read': frame.data['read'],
                'description': 'Setup {} to [0x{:02X}] + {}'.format(str_direction, bytes_address[0], str_ack)
            })
        elif frame.type == "data":
            if(self.type_history != "data"):
                print('Data:')
                self.data_len = 0
            self.data_len = self.data_len + 1
            str_data = frame.data['data'].hex().upper()
            print(str_data, end =" ")
            if(self.data_len >= self.data_print_len):
                self.data_len = 0
                print("")
            if frame.data['ack'] == False:
                print("NAK")
            return AnalyzerFrame('data', frame.start_time, frame.end_time, {
                'ack': frame.data['ack'],
                'data': frame.data['data'],
                'description':'0x{:02X} + {}'.format(frame.data['data'][0], 'ACK' if frame.data['ack'] else 'NAK')
            })
        elif frame.type == "stop":
            print('Stop')
            return AnalyzerFrame('stop', frame.start_time, frame.end_time, {
            })