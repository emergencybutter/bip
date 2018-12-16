#!/bin/bash
for i in src/*.[ch] ; do
	clang-format -i $i
done
for i in tests/*.c ; do
	clang-format -i $i
done
