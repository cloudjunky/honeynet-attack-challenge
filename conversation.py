__author__ = 'michaelbaker'


class Conversation(object):
    instances = []

    def __init__(self):
        self.addresses = ''
        self.fpackets = []
        self.bpackets = []
        self.ftimestamps = []
        self.btimestamps = []
        self.fpackets = []
        self.bpackets = []
        self.fdata = ''
        self.bdata = ''
        Conversation.instances.append(self)

    @property
    def duration(self):
        all_timestamps = self.ftimestamps + self.btimestamps
        if len(all_timestamps) < 2:
            return "NaN"
        else:
            return max(all_timestamps) - min(all_timestamps)

    @property
    def first_and_last(self):
        all_timestamps = self.ftimestamps + self.btimestamps
        if len(all_timestamps) < 2:
            return 0.0, 0.0
        else:
            return min(all_timestamps), max(all_timestamps)



