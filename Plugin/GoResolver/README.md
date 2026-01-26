# GoResolver - Plugin

This plugin allows you to use GoResolver from your SRE tool of choice (IDA Pro / Ghidra).

## Featureset

This plugin gives you the option to either analyze the current file, or to import a previously generated GoResolver report.

When performing an analysis with a Go version for the first time, GoResolver will install the requested Go version which may increase the analysis run time. When multiple Go versions are installed, it is possible to select a specific Go version to perform the analysis with from the plugin's user interface.

When importing a previously generated GoResolver report, simply point the plugin to the report file to fill in the recovered symbols in your SRE.

### Managing Go versions

The IDA plugin has the ability to manage the installed Go versions from the plugin's user interface.
When using Ghidra, it is necessary to use the CLI to install or remove Go versions.

## How to install

This plugin depends on GoResolver to function. Regardless of the SRE tool you use, it is likely that you will need to setup a Python virtual environment with GoResolver installed to be able to install this plugin.

### IDA

The easiest way to install the GoResolver plugin is through hcli and Hex-Rays plugin repository. Simply run the following command:

```bash
hcli plugin install GoResolver
```

This will install the plugin and its required dependencies.

It is also possible to install with the plugin archive downloaded from this repository's release section with the following command:

```bash
hcli plugin install GoResolver.zip
```

To install the IDA plugin from source copy the following files to the `~/.idapro/plugins/goresolver` directory :

```
common/
goresolver_ida.py
ida-plugin.json
ida_config_form.py
```

### Ghidra

To Install the Ghidra plugin copy the following files to your choosed plugin directory, Ex: `~/.ghidra/plugins/goresolver` :

```
common/
goresolver_ghidra.py
```

Then add the directory to Ghidra's Script Manager.
