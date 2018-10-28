#echo $PWD

cd openssl
# For Linux
./config enable-tls1_3 --prefix=$PWD/../build/openssl
make -j$(nproc)
make install_sw
cd ..

cd ngtcp2
autoreconf -i
# For Mac users who have installed libev with MacPorts, append
# ',-L/opt/local/lib' to LDFLAGS, and also pass
# CPPFLAGS="-I/opt/local/include" to ./configure.
./configure PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib" --prefix=$PWD/../build/ngtcp2
make -j$(nproc) check
make install
cd ..

#cd nghq
./bootstrap
./configure PKG_CONFIG_PATH=$PWD/../ngtcp2/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../ngtcp2/build/lib" --prefix=$PWD/../build/nghq
make install
