# STIGs

The purpose of this repository is to provide scripts to automate Security Technical Implementation Guide (STIG) checks. These are technical security standards created by the Defense Information Systems Agency (DISA). DISA releases standards utilizing DoD definitions and certificates. Not every check is applicable to your device or organization. Every check is scripted though to provide complete coverage; simple ignore the checks you don't need. The MCM.ps1 file is meant to be deployed with Microsoft Configuration Manager, with all output files logged to a central location. Then the MCM assessment.ps1 file analyzes all these outputs and reports on non-compliance.
