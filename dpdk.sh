sudo apt update
sudo apt install -y build-essential meson ninja-build \
    libnuma-dev libpcap-dev python3-pyelftools \
    pkg-config

git clone https://github.com/DPDK/dpdk.git
cd dpdk

meson setup build
cd build
ninja


sudo ninja install
sudo ldconfig

grep Huge /proc/meminfo

sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

sudo modprobe vfio-pci

sudo modprobe uio
sudo modprobe uio_pci_generic

sudo ./usertools/dpdk-devbind.py --status


sudo dpdk-devbind.py -b vfio-pci 0000:03:00.0

flusing on linux

ip addr flush dev ifname
ip link set dev ifname down/up