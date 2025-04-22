# onion-vanity-address

Generates Tor Onion Service v3 [vanity addresses](https://community.torproject.org/onion-services/advanced/vanity-addresses/) with a specified prefix.

Can also generate vanity [client authorization](https://community.torproject.org/onion-services/advanced/client-auth/) keypairs.

Uses an optimized search algorithm based on curve coordinate symmetry, faster than `mkp224o` in like-for-like benchmarks.

## Usage

Install:
```sh
go install github.com/offset/onion-vanity-address@latest
```

Run:
```
$ onion-vanity-address hidden
Found hidden... in 6s after 734002132 attempts (133083751 attempts/s)
---
hostname: hiddenv5vi6en7xlnns3gj6wa3q5zhqrum6izn6hrwnrw3fiplbgpjyd.onion
hs_ed25519_public_key: PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAA6BjI2vao8Rv7ra2WzJ9YG4dyeEaM8jLfHjZsbbKh6wg==
hs_ed25519_secret_key: PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAABI0dtnOsAw0DPamQtZx/6G83IUxdByrnWakYApdO/QcJaicGyBL8wKTwbqMDsLgyZJigdTqfvUyWDxWU3mVPF/
```

Or via Docker:
```sh
docker pull ghcr.io/offset/onion-vanity-address:latest
docker run ghcr.io/offset/onion-vanity-address:latest hidden
```

To configure a hidden service keypair, decode the base64 secret key into the `hs_ed25519_secret_key` file, remove the existing `hs_ed25519_public_key` and `hostname` files, then reload Tor:
```console
$ echo PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAABI0dtnOsAw0DPamQtZx/6G83IUxdByrnWakYApdO/QcJaicGyBL8wKTwbqMDsLgyZJigdTqfvUyWDxWU3mVPF/ | base64 -d > /var/lib/tor/hidden_service/hs_ed25519_secret_key
$ rm /var/lib/tor/hidden_service/hs_ed25519_public_key
$ rm /var/lib/tor/hidden_service/hostname
$ systemctl reload tor

$ cat /var/lib/tor/hidden_service/hostname
hiddenv5vi6en7xlnns3gj6wa3q5zhqrum6izn6hrwnrw3fiplbgpjyd.onion
```

### Multiple prefixes

Search several prefixes simultaneously, returning the first match:
```sh
onion-vanity-address zwiebel cipolla cebolla
```

Shorter prefixes match more often when prefix lengths differ.

### Client authorization

Generate a vanity client authorization keypair:
```console
$ onion-vanity-address --client CIPHER
Found CIPHER... in 1s after 193321042 attempts (173957834 attempts/s)
---
public_key: CIPHERSSZ5BEZGGAU6E2NQKSXMQIX2N2E5JME2727FFXGRQQYEJA
private_key: SUHVE2HHTAZ25FV2MOQBA6EU6WL7MIBIPHGYB3SPYC6UEMSN3ECA
```

Add the public key to the service's `authorized_clients` directory:
```console
$ echo descriptor:x25519:CIPHERSSZ5BEZGGAU6E2NQKSXMQIX2N2E5JME2727FFXGRQQYEJA > /var/lib/tor/hidden_service/authorized_clients/cipher.auth
$ systemctl reload tor
```

Provide the matching private key in Tor Browser when authentication is requested.

For all flags and options:
```sh
onion-vanity-address --help
```

## Performance

Sustained throughput on an AMD Ryzen 7 PRO 8700GE (8 cores / 16 threads, 5.18 GHz boost, AVX-512), 64 GB RAM:

```console
$ onion-vanity-address --timeout 60s goodluckwiththisprefix
Stopped searching goodluckwiththisprefix... after 1m0s and 7702450134 attempts (128345505 attempts/s)
```

```console
$ onion-vanity-address --timeout 120s goodluckwiththisprefix
Stopped searching goodluckwiththisprefix... after 2m0s and 15072715508 attempts (125591236 attempts/s)
```

Roughly **125M keys/s** sustained. Performance scales close to linearly with physical cores; SMT adds about 5%. AVX-512 capability does not change throughput because the field arithmetic is hand-written assembly that already uses the optimal scalar instructions.

Estimated search time (single host, 125M keys/s):

| Prefix length | Median time | Worst case (p=99%) |
|---------------|-------------|-------------------:|
| 4 chars       |    0.01 s   |        0.04 s      |
| 5 chars       |    0.2 s    |        1.2 s       |
| 6 chars       |    7 s      |        40 s        |
| 7 chars       |    4 min    |       21 min       |
| 8 chars       |    2 h      |       11 h         |
| 9 chars       |    3 days   |       15 days      |

Each additional prefix character multiplies expected search time by 32.

## Kubernetes

Distributed search across a cluster without exposing the secret key. See `demo-k8s.yaml`.

```console
$ # Locally generate a secure starting keypair (or reuse an existing one).
$ onion-vanity-address start
Found start... in 1s after 26921387 attempts (43429741 attempts/s)
---
hostname: startxxytwan7gfm6ojs6d2auwhwjhysjz3c5j2hd7grlokzmd4reoqd.onion
hs_ed25519_public_key: PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAACUwRne+J2A35is85MvD0Clj2SfEk52LqdHH80VuVlg+Q==
hs_ed25519_secret_key: PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAABgZ5a7kuS0N1jaA12gtsqI87RPS1eqSj4KWpwXukWtV7pFj6gS200J96P8JDWTpvx000KF3r4l+xYcIJszhPZk

$ # Edit demo-k8s.yaml: prefix, starting public key, parallelism, resource limits.

$ kubectl apply -f demo-k8s.yaml
job.batch/ova created

$ kubectl wait --for=condition=complete job/ova --timeout=1h

$ kubectl logs jobs/ova
Found lukovitsa... in 23m14s after 1003371311076 attempts (719798516 attempts/s)
---
hostname: lukovitsa6jy7sldxvdw7wwzdmf5sezbwgr5uf57kkhi3jep25g2d2id.onion
offset: sgowAsMLwBk=

$ # Locally derive the vanity keypair by applying the offset to the starting secret key.
$ echo PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAABgZ5a7kuS0N1jaA12gtsqI87RPS1eqSj4KWpwXukWtV7pFj6gS200J96P8JDWTpvx000KF3r4l+xYcIJszhPZk | onion-vanity-address --offset=sgowAsMLwBk=
---
hostname: lukovitsa6jy7sldxvdw7wwzdmf5sezbwgr5uf57kkhi3jep27gzjlid.onion
hs_ed25519_public_key: PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAABdFOqicgeTj8ljvUdv2tkbC9kTIbGj2he/Uo6NpI/XzQ==
hs_ed25519_secret_key: PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAAoaPTTqGQGyF3aA12gtsqI87RPS1eqSj4KWpwXukWtVyHuiixSBYjSDLiBwGmeqebH1FX7vsHRPBrojpTFiCGQ

$ kubectl delete job ova
```

## Similar tools

- [mkp224o](https://github.com/cathugger/mkp224o)
- [oniongen-go](https://github.com/rdkr/oniongen-go)

## The search algorithm

A Tor Onion Service [address](https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt) is derived from an ed25519 public key. This tool generates candidate public keys until it finds one whose onion encoding starts with the requested prefix.

An ed25519 keypair consists of:
- a 32-byte secret key (scalar): a random value
- a 32-byte public key (point): derived by scalar multiplication of the base point by the scalar

The public key is the 32-byte y-coordinate of a point on a [Twisted Edwards curve](https://datatracker.ietf.org/doc/html/rfc8032) equivalent to [Curve25519](https://datatracker.ietf.org/doc/html/rfc7748#section-4.1).

Both `mkp224o` and `onion-vanity-address` use the additive structure of the curve to skip a full scalar multiplication per candidate. Point addition needs an expensive field inversion, so both batch them via the Montgomery trick (one inversion per batch).

The performance gap is in coordinate handling: `mkp224o` calculates both coordinates per candidate. This implementation exploits curve symmetry and computes only y-coordinates, cutting field operations.

Amortized cost: **5M + 2A** per candidate key (M = field multiplication, A = field addition).

## Related

- [vanity25519](https://github.com/AlexanderYastrebov/vanity25519): general Curve25519 vanity key generator.
- [wireguard-vanity-key](https://github.com/AlexanderYastrebov/wireguard-vanity-key): WireGuard vanity key generator.
- [age-vanity-keygen](https://github.com/AlexanderYastrebov/age-vanity-keygen): age X25519 vanity identity generator.

## License

BSD-3-Clause. See `LICENSE`.
