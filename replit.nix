{ pkgs }: {
	deps = [
		# autoconf automake libtool curl make g++ unzip
		pkgs.autoconf
		pkgs.automake
		pkgs.libtool
		pkgs.curl
		pkgs.cmake
		pkgs.gcc
		pkgs.unzip
		pkgs.nodejs-16_x
		pkgs.nodePackages.typescript-language-server
		pkgs.yarn
	];
}