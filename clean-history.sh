#!/bin/bash
git checkout --orphan latest_branch
git add -A
git commit -am "cleanup history"
git branch -D master
git branch -m master
