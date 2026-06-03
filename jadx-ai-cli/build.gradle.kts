plugins {
	id("jadx-library")
	application
	id("com.gradleup.shadow") version "8.3.8"
}

application {
	mainClass.set("jadx.ai.cli.JadxAICLI")
	applicationName = "jadx-ai"
	applicationDefaultJvmArgs =
		listOf(
			"-Xms256M",
			"-XX:MaxRAMPercentage=70.0",
		)
}

dependencies {
	implementation(project(":jadx-core"))

	implementation("info.picocli:picocli:4.7.5")
		implementation("com.android.tools.build:apksig:8.13.1")
	implementation("com.google.code.gson:gson:2.10.1")
	implementation("org.slf4j:slf4j-api:2.0.9")
	runtimeOnly("ch.qos.logback:logback-classic:1.4.11")

	testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
}

tasks.test {
	useJUnitPlatform()
}

tasks.jar {
	manifest {
		attributes("Main-Class" to "jadx.ai.cli.JadxAICLI")
	}
}

tasks.shadowJar {
	mergeServiceFiles()
	manifest {
		attributes("Main-Class" to "jadx.ai.cli.JadxAICLI")
	}
}
