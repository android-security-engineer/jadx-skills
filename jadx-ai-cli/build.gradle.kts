plugins {
	id("jadx-library")
	application
}

application {
	mainClass.set("jadx.ai.cli.JadxAICLI")
}

dependencies {
	implementation(project(":jadx-core"))
	implementation(project(":jadx-cli"))

	implementation("info.picocli:picocli:4.7.5")
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
