#!/usr/bin/env python

from stream import *

if __name__ == '__main__':
    n = StreamProcess()
    args = n.parse_args()
    n.run(args)
