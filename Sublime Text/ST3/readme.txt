================================
Package Installation
================================

Sublime Text is extended through the use of Packages.  Usually, you would install the Package Manager package and then use this to install other packages.  However, on the managed (Production) network you will invariably encounter firewall issues trying to access the ST Package repo.  For this reason some useful packages are included as part of this restribution.

Packages are installed to the ST3 AppData root at the following path:  $User\AppData\Roaming\Sublime Text 3\

1) Copy any sublime-package files from the deployment 'installed packages' folder to the AppData 'installed packages' folder.
2) Unzip any zip files in the deployment 'packages' folder to the AppData 'packages' folder.
3) To enable the Predawn theme, paste the following into the Preferences | Settings - User file:

{
	"auto_find_in_selection": true,
	"color_scheme": "Packages/Predawn/predawn.tmTheme",
	"font_size": 10,
	"ignored_packages":
	[
		"Vintage"
	],
	"tabs_small": true,
	"theme": "predawn-DEV.sublime-theme"
}


