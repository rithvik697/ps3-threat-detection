#!/bin/bash
# One-command pipeline: generate logs then evaluate them
python app1_generator/generator.py --lines 50000 --attacks brute_force,port_scan --out data/logs.json
echo "----"
python app2_evaluator/evaluator.py --logs data/logs.json --cve data/cve_cache.json
