FROM debian:stable-slim

SHELL ["/bin/bash", "-c"]

WORKDIR /root

# The "wine" package provides a convenience wrapper that we need
RUN dpkg --add-architecture i386 && apt-get update && apt-get install --no-install-recommends -y \
        autoconf automake libtool make \
        gcc-mingw-w64-x86-64-win32 \
        gcc-mingw-w64-i686-win32 \
        git ca-certificates wine64 wine32:i386 wine python3-simplejson python3-six msitools winbind procps && \
# Workaround for `wine` package failure to employ the Debian alternatives system properly.
    ln -s /usr/lib/wine/wine64 /usr/bin/wine64 && \
# Set of tools for using MSVC on Linux.
    git clone https://github.com/mstorsjo/msvc-wine && \
    mkdir /opt/msvc && \
    python3 msvc-wine/vsdownload.py --accept-license --dest /opt/msvc Microsoft.VisualStudio.Workload.VCTools && \
# Since commit 2146cbfaf037e21de56c7157ec40bb6372860f51, the
# msvc-wine effectively initializes the wine prefix when running
# the install.sh script.
    msvc-wine/install.sh /opt/msvc && \
# Wait until the wineserver process has exited before closing the session,
# to avoid corrupting the wine prefix.
    while (ps -A | grep wineserver) > /dev/null; do sleep 1; done
