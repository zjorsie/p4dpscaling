#!/bin/bash
CURDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

DIRNAME='graphs'
if [ ! -d $DIRNAME ]; then
  mkdir $CURDIR/$DIRNAME
fi
p4c-graphs --std 14 $CURDIR/firewall.p4 --graphs-dir $CURDIR/$DIRNAME/

files=`ls $CURDIR/$DIRNAME`
FILEARR=()
for f in $CURDIR/$DIRNAME/*.dot; do
    # add to array
    FILEARR+=("$f")
done
for f in "${FILEARR[@]}"; do
    filebase=`echo "$f" | sed 's/\.dot$//'`
    dot -Tpng "$f" > "$filebase".png
done
