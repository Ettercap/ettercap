#! /usr/bin/env lua
prog = {
  name        = arg[0]:gsub ("^.*/", ""),,
  version     = "VERSION (DATE) by AUTHOR <EMAIL>)",
  purpose     = "ONE LINE DESCRIPTION OF WHAT THIS PROGRAM DOES",
  description = "optional longer description of how to use this program",
  copyright   = "Copyright (C) YEAR COPYRIGHT-HOLDER",
  notes       = "Usage footer messasge",
}


require "std"


-- Process a file
function main (file, number)
end


-- Command-line options
prog.options = {
  getopt.Option {{"test", "t"},
    "test option"},
}

-- Main routine
getopt.processArgs (prog)
io.processFiles (main)


-- Changelog

--   0.1  Program started
