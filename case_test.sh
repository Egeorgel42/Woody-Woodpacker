set -ex

if [ ! -e "woody_woodpacker" ]; then
    make
fi

gcc sample.c -m64 -o sample64
gcc sample.c -m32 -o sample32
gcc sample.c -m64 -no-pie -o sample64_nopie
gcc sample.c -m32 -no-pie -o sample32_nopie

echo
rm -f woody
./woody_woodpacker sample64
./sample64
./woody

echo
rm -f woody
./woody_woodpacker sample32
./sample32
./woody

echo
rm -f woody
./woody_woodpacker sample64_nopie
./sample64_nopie
./woody

echo
rm -f woody
./woody_woodpacker sample32_nopie
./sample32_nopie
./woody

set +ex