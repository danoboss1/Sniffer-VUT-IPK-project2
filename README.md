# Netwrok sniffer
### VUT University : IPK_2024 Project2

Terminálová aplikácia Network Sniffer, slúži na zachytávanie, filtrovanie paketov na určitom rozhraní 
a následne výpis najdôležitejších informácií na štandardný výstup

- Network Sniffer obsahuje podrobnú dokumentáciu: xsehno02.pdf


## Usage
### Compile 

```sh
make
```

### Clean build

```sh
make clean
make
```
### Run
After compilation it can be run using following command:
```sh
./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
```


## Technical details
Program was written in C language.  

## License
The program was made according to MIT Licence.

## Výstupný formát 
```sh
2024-04-14T08:26:34.917+00:00             # Čas v RFC3339
src MAC: some value                       # Zdrojova MAC adresa
dst MAC: some value                       # Cieľová MAC adresa
frame length: 71 bytes                    # Dľžka rámca v bytoch
src IP: some value                        # Zdrojova IP adresa
dst IP: some value                        # Cieľová IP adresa  
src port: 50982                           # Zdrojový port
dst port: 53                              # Cieľový port

# Data
0x0000: 52 54 00 12 35 02 08 00 27 f6 94 75 08 00 45 00    RT..5...'..u..E.
0x0010: 00 39 9b f9 00 00 40 11 22 02 0a 00 02 0f c0 a8    .9....@.".......
0x0020: f0 01 c7 26 00 35 00 25 bc ef a5 ad 01 00 00 01    ...&.5.%........
0x0030: 00 00 00 00 00 00 07 64 69 73 63 6f 72 64 03 63    .......discord.c
0x0040: 6f 6d 00 00 01 00 01                               om.....
```
