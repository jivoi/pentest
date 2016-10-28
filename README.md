## So, You Want to be a Rock Star?
## Follow instructions, it`s very easy!

```bash
$ git clone https://github.com/jivoi/pentest.git ./offsecfw && cd offsecfw
$ mix_ping_sweep.py 192.168.56.1-254 ./results
$ mix_port_scan.sh -t ./results/targets.txt -p all
$ mix_recon.py ./results/targets.txt
```