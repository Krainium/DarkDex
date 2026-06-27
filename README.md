# 🟣 DarkDex

> ⚡ powerful tool to bypass ijiami 4th Gen.

🧬 DarkDex pulls the real dex out of packed android apps. it reads the running app memory and rebuilds the dex even when the header is wiped, so it works on iJiami including the 4th gen vmp, other packers, and plain apps too.

it comes in two parts.

🖥️ darkdex.sh runs on a redroid host. it reads the target process memory from outside the android sandbox, so nothing inside the app can spot it.

📱 darkdex.apk runs on the phone or emulator itself. root mode does a full memory dump. no root mode pulls the on disk dex.

## 📥 setup

clone it

```
git clone https://github.com/Krainium/DarkDex.git
cd DarkDex
```

### 🖥️ host tool (darkdex.sh)

you need a linux host running redroid, which is android inside docker. use the arm64 image so it runs arm apps. the host kernel needs the binder modules.

load binder on the host

```
sudo modprobe binder_linux devices="binder,hwbinder,vndbinder"
```

start redroid and connect adb

```
docker run -itd --privileged --name redroid \
  -v ~/redroid_data:/data -p 5555:5555 \
  redroid/redroid:11.0.0 \
  androidboot.redroid_width=720 androidboot.redroid_height=1280
adb connect localhost:5555
```

build the native cores on the host

```
cd native
g++ -O2 -std=c++17 -o darkdex_carve   darkdex_carve.cpp
g++ -O2 -std=c++17 -o darkdex_recover darkdex_recover.cpp
g++ -O2 -std=c++17 -o darkdex_intel   darkdex_intel.cpp
cd ..
```

run it. pass an apk and it installs it for you, or pass a package that is already installed.

```
./host/darkdex.sh app.apk
./host/darkdex.sh com.some.app
```

dumps land in dumps/<package>/ with the carved dex, the recovered dex, and an intel file with the backend urls, the class map and the packer id.

### 📱 the app (darkdex.apk)

grab the apk from the releases page and install it

```
adb install -r -g darkdex.apk
```

or build it yourself

```
cd app
./gradlew :app:assembleDebug
adb install -r -g app/build/outputs/apk/debug/app-debug.apk
```

open DarkDex, pick an app from the list, and it dumps. on a rooted device or emulator the badge turns green and you get the full memory dump. without root it pulls the on disk dex. there is a search box and a force no root switch.

## 🔧 how it works

the full writeup is in ijiami.md.

## 📸 screens

✨ splash

![splash](docs/splash.png)

📲 app with the root badge, search box and toggle

![app](docs/app.png)

🧩 dump result with the mode badge

![dump](docs/dump.png)

💻 a dump running in the terminal

![terminal](docs/terminal.png)

## 🎓 for educational use

use it only on apps you own or are allowed to test. for research and learning.
