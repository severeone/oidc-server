#!/bin/bash
./gradlew --info clean initLocal docker
./gradlew -b local.gradle --info dockerStop dockerRemoveContainer dockerRun connectToNetwork