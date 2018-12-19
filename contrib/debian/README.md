
Debian
====================
This directory contains files used to package divcd/divc-qt
for Debian-based Linux systems. If you compile divcd/divc-qt yourself, there are some useful files here.

## divc: URI support ##


divc-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install divc-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your divcqt binary to `/usr/bin`
and the `../../share/pixmaps/divc128.png` to `/usr/share/pixmaps`

divc-qt.protocol (KDE)

