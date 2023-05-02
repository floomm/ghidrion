# Ghidrion

## How to contribute

There are a few requirements:

- Java 17
- [Ghidra 10.2.3](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_10.2.3_build)
- Eclipse IDE with GhidraDev extension

1. `git clone https://github.com/silvan-flum/ghidrion.git`
2. In Eclipse, import the cloned Ghidrion project:
   1. `File` -> `Import` -> `Existing Gradle Project` -> `Next` -> Choose `ghidrion/Ghidrion` as Project root directory -> `Next` -> `Next` -> `Finish`
3. In Eclipse, create a new Ghidra Module Project:
   1. **Important**: Do **not** create this project in the cloned ghidrion repository
   2. `GhidraDev` -> `New` -> `Ghidra Module Project...` -> Project name: `GhidrionSetup` -> `Next` -> Uncheck all except `Plugin` -> `Next` -> Choose Ghidra 10.2.3 -> `Next` -> `Finish`
4. Copy `GhidrionSetup/.classpath` and `GhidrionSetup/.project` to `ghidrion/Ghidrion` (replace existing .classpath and .project)
5. You can now delete the `GhidrionSetup` directory if you wish
6. Open `ghidrion/Ghidrion/.project` and replace `<name>GhidrionSetup</name>` with `<name>Ghidrion</name>`
7. Open `ghidrion/Ghidrion` in a terminal:
   1. `gradle build`
8. In Eclipse, right-click on the Ghidrion project -> `Build Path` -> `Configure Build Path...` -> `Libraries` -> `Classpath` -> `Add JARs...` -> `Ghidrion` -> `lib` -> Choose all .jar files -> `OK` -> `Apply and Close`
9. To run the project: Right-click on the Ghidrion project -> `Run as` -> `Ghidra`
