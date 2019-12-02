If you for some reason do not want to use our script which create a configuration file for you then this guide is for you.

    Install WireGuard by following the official instructions

echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list

printf 'Package: *\nPin: release a=unstable\nPin-Priority: 150\n' > /etc/apt/preferences.d/limit-unstable

apt update

apt install wireguard

We will start by using the wg(8) tool to generate private and public keys as seen in the example below.

AzireVPN conf file

wg genkey | tee privatekey | wg pubkey > publickey

cat privatekey
65G7oyb9jGxFXSCceTuFPHjjbPF2WVOCeNJ1SgPzzWk=

cat publickey
oP4Hdje7viyO+6Hz6QKQgHqD55w+Km9uZ0shmTFU0GI=

You are now ready to authenticate to our service by sending your login credentials and public key. As seen in the example below, we use curl to post the data to our WireGuard server in Stockholm (se1).

API request

curl -d username=REPLACE --data-urlencode password=REPLACE --data-urlencode pubkey=REPLACE https://api.azirevpn.com/v1/wireguard/connect/se1
{
    "status": "success",
    "data": {
        "DNS": "193.180.164.2, 2a03:8600:1001::2",
        "Address": "10.18.1.182/24, 2a03:8600:1001:1080::10b4/64",
        "PublicKey": "bdR5gm5vcrm9N9I7BeQqHOgrmQApSGIe9qc1homBjk8=",
        "Endpoint": "193.180.164.60:51820"
    }
}




/etc/wireguard/example-se1.conf example file

[Interface]
PrivateKey = 65G7oyb9jGxFXSCceTuFPHjjbPF2WVOCeNJ1SgPzzWk=
DNS = 193.180.164.2, 2a03:8600:1001::2
Address = 10.18.1.182/24, 2a03:8600:1001:1080::10b4/64

[Peer]
PublicKey = bdR5gm5vcrm9N9I7BeQqHOgrmQApSGIe9qc1homBjk8=
Endpoint = 193.180.164.60:51820
AllowedIPs = 0.0.0.0/0, ::/0

