#!/bin/bash

 ps -ef |grep camostream | awk '{print $2}' | xargs kill -9
