plugins {
	id("jadx-library")
	id("com.gradleup.shadow") version "8.3.8"
}

// jadx-ai-gui is a faithful port of zinja-coder/jadx-ai-mcp (Apache 2.0) adapted into
// this monorepo. It is a JADX GUI plugin: an embedded Javalin HTTP server exposing the
// live decompiler/GUI state. Javalin 6.7 requires Java 17 at runtime, so this single
// module overrides the repo-wide Java 11 target (the build/CI JVM is 21).

dependencies {
	// Compile against the GUI + core source modules instead of the external jadx-all jar.
	compileOnly(project(":jadx-gui"))
	compileOnly(project(":jadx-core"))

	implementation("io.javalin:javalin:6.7.0")
	implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
	implementation("com.google.code.gson:gson:2.10.1")

	testImplementation(project(":jadx-gui"))
	testImplementation(project(":jadx-core"))
}

java {
	sourceCompatibility = JavaVersion.VERSION_17
	targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile> {
	options.release.set(17)
}
