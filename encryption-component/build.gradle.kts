version = "1.0.0"
val nexusRepo = "https://nexus-ar.veritran.net/repository/tokenization/"
val nexusUser:String = ""
val nexusPassword:String = ""

plugins {
    java
    kotlin("jvm") version "1.4.21"
    application
    `maven-publish`
}

repositories {
    mavenCentral()
    jcenter()
    maven {
        name = "nexus"
        url = uri(nexusRepo)
    }
}

publishing {
    repositories {
        maven {
            url = uri(nexusRepo)
            credentials {
                username = nexusUser
                password = nexusPassword
            }
        }
    }

    publications {
        create<MavenPublication>("maven") {
            groupId = "com.veritran.tokenization"
            artifactId = "encryption-component"
            from(components["java"])
            artifact("encryption-component-fat-$version.jar")
        }
    }
}


dependencies {
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    implementation("org.junit.jupiter:junit-jupiter:5.4.2")
    implementation("org.bitbucket.b_c:jose4j:0.7.2")

    implementation("com.nimbusds:nimbus-jose-jwt:9.1.2")

    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.9.8")

    implementation("com.beust:klaxon:5.0.1")

    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit")
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "1.8"
}
//
//val fatJar = task("fatJar", type = Jar::class) {
//    baseName = "${project.name}"
//    manifest {
//        attributes["Implementation-Title"] = "Gradle Jar File Example"
//        attributes["Implementation-Version"] = version
//        attributes["Main-Class"] = "com.mkyong.DateUtils"
//    }
//    from(configurations.runtimeClasspath.get().map({ if (it.isDirectory) it else zipTree(it) }))
//    with(tasks.jar.get() as CopySpec)
//}



//tasks.jar {
//    manifest {
//        attributes(
//            mapOf(
//                "Implementation-Title" to project.name,
//                "Implementation-Version" to project.version
//            )
//        )
//    }
//}

//
//tasks.assemble {
//    dependsOn(fatJar)
//}