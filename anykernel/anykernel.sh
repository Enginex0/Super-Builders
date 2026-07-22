### AnyKernel3 Ramdisk Mod Script
## osm0sis @ xda-developers

### AnyKernel setup
# global properties
properties() { '
kernel.string=Genevn Next Kernel by Slm015
do.devicecheck=1
do.modules=0
do.systemless=1
do.cleanup=1
do.cleanuponabort=0
device.name1=genevn
device.name2=genevn_g
device.name3=
device.name4=
device.name5=
supported.versions=
supported.patchlevels=
supported.vendorpatchlevels=
'; } # end properties

### AnyKernel install

# boot shell variables
BLOCK=boot;
IS_SLOT_DEVICE=1;
RAMDISK_COMPRESSION=auto;
PATCH_VBMETA_FLAG=auto;

# import functions/variables and setup patching - see for reference (DO NOT REMOVE)
. tools/ak3-core.sh;

# boot install
split_boot; # skip ramdisk unpack for standard boot since kernel lives here in GKI 2.0
flash_boot; # flash the new kernel image directly to the boot partition
## end boot install


## init_boot files attributes
init_boot_attributes() {
set_perm_recursive 0 0 755 644 $RAMDISK/*;
set_perm_recursive 0 0 750 750 $RAMDISK/init* $RAMDISK/sbin;
} # end attributes

# init_boot shell variables
BLOCK=init_boot;
IS_SLOT_DEVICE=1;
RAMDISK_COMPRESSION=auto;
PATCH_VBMETA_FLAG=auto;

# reset for init_boot patching
reset_ak;

# init_boot install
dump_boot; # unpack the first-stage ramdisk where KernelSU/overlay.d hooks inject
write_boot; # repack and write the modified ramdisk back to init_boot
## end init_boot install

