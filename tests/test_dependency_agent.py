import json
import tempfile
import unittest
from pathlib import Path

from agents.dependency_agent import parse_dependencies


class DependencyAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def deps(self, ecosystem=None):
        values = parse_dependencies(str(self.root))
        return [d for d in values if ecosystem is None or d["ecosystem"] == ecosystem]

    def package(self, data):
        return self.put("package.json", json.dumps(data))

    # Python requirements behavior
    def test_01_exact_pin(self):
        self.put("requirements.txt", "requests==2.31.0\n")
        self.assertEqual(self.deps("PyPI")[0]["version"], "2.31.0")

    def test_02_version_range(self):
        self.put("requirements.txt", "requests>=2.0\n")
        self.assertEqual(self.deps("PyPI")[0]["version"], ">=2.0")

    def test_03_extras(self):
        self.put("requirements.txt", "requests[security]==2.31.0\n")
        self.assertEqual(self.deps("PyPI")[0]["name"], "requests")

    def test_04_comments_and_blanks(self):
        self.put("requirements.txt", "# comment\n\nrequests==2\n")
        self.assertEqual(len(self.deps("PyPI")), 1)

    def test_05_duplicate_python_dependencies(self):
        self.put("requirements.txt", "Requests==2\nrequests==2\n")
        self.assertEqual(len(self.deps("PyPI")), 1)

    def test_06_environment_marker(self):
        self.put("requirements.txt", "foo>=1; python_version < '4'\n")
        self.assertEqual(self.deps("PyPI")[0]["version"], ">=1")

    def test_07_invalid_requirement_skipped(self):
        self.put("requirements.txt", "not a valid requirement !!!\n")
        self.assertEqual(self.deps("PyPI"), [])

    def test_08_empty_requirements(self):
        self.put("requirements.txt", "")
        self.assertEqual(self.deps(), [])

    def test_09_missing_requirements(self):
        self.assertEqual(self.deps(), [])

    def test_10_direct_url_requirement(self):
        self.put("requirements.txt", "demo @ https://example.test/demo.whl\n")
        self.assertEqual(self.deps("PyPI")[0]["version"], "https://example.test/demo.whl")

    # package.json behavior
    def test_11_dependencies(self):
        self.package({"dependencies": {"left-pad": "1.3.0"}})
        self.assertEqual(self.deps("npm")[0]["version"], "1.3.0")

    def test_12_dev_dependencies(self):
        self.package({"devDependencies": {"jest": "^29.0"}})
        self.assertEqual(self.deps("npm")[0]["name"], "jest")

    def test_13_optional_dependencies(self):
        self.package({"optionalDependencies": {"fsevents": "~2.0"}})
        self.assertEqual(self.deps("npm")[0]["version"], "~2.0")

    def test_14_peer_dependencies(self):
        self.package({"peerDependencies": {"react": ">=18"}})
        self.assertEqual(self.deps("npm")[0]["version"], ">=18")

    def test_15_scoped_package(self):
        self.package({"dependencies": {"@scope/pkg": "1.2.3"}})
        self.assertEqual(self.deps("npm")[0]["name"], "@scope/pkg")

    def test_16_npm_version_range(self):
        self.package({"dependencies": {"x": "^1.2.0"}})
        self.assertEqual(self.deps("npm")[0]["version"], "^1.2.0")

    def test_17_malformed_json(self):
        self.put("package.json", "{")
        self.assertEqual(self.deps("npm"), [])

    def test_18_duplicate_package_sections(self):
        self.package({"dependencies": {"x": "1"}, "devDependencies": {"x": "1"}})
        self.assertEqual(len(self.deps("npm")), 1)

    def test_19_wildcard_version(self):
        self.package({"dependencies": {"x": "*"}})
        self.assertEqual(self.deps("npm")[0]["version"], "*")

    # Lockfiles
    def test_20_lockfile_v2(self):
        self.put("package-lock.json", json.dumps({"lockfileVersion": 2, "packages": {"": {}, "node_modules/a": {"version": "1.0"}}}))
        self.assertEqual(self.deps("npm")[0]["version"], "1.0")

    def test_21_lockfile_v3(self):
        self.put("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "2.0"}}}))
        self.assertEqual(self.deps("npm")[0]["version"], "2.0")

    def test_22_lockfile_v1(self):
        self.put("package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0"}}}))
        self.assertEqual(self.deps("npm")[0]["version"], "1.0")

    def test_23_nested_lock_dependencies(self):
        self.put("package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1", "dependencies": {"b": {"version": "2"}}}}}))
        self.assertEqual({d["name"] for d in self.deps("npm")}, {"a", "b"})

    def test_24_scoped_lock_package(self):
        self.put("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"node_modules/@scope/pkg": {"version": "1"}}}))
        self.assertEqual(self.deps("npm")[0]["name"], "@scope/pkg")

    def test_25_transitive_lock_package(self):
        self.put("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1"}, "node_modules/a/node_modules/b": {"version": "2"}}}))
        self.assertEqual(len(self.deps("npm")), 2)

    def test_26_lock_precedence(self):
        self.package({"dependencies": {"a": "^1"}})
        self.put("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.4.0"}}}))
        found = self.deps("npm")
        self.assertEqual([(d["version"], d["source_file"]) for d in found], [("1.4.0", "package-lock.json")])

    def test_27_malformed_lock_falls_back(self):
        self.package({"dependencies": {"a": "^1"}})
        self.put("package-lock.json", "{")
        self.assertEqual(self.deps("npm")[0]["version"], "^1")

    def test_28_lock_root_excluded(self):
        self.put("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "root", "version": "1"}}}))
        self.assertEqual(self.deps("npm"), [])

    # General scanning and normalization
    def test_29_missing_project(self):
        self.assertEqual(parse_dependencies(str(self.root / "missing")), [])

    def test_30_ignored_directories(self):
        for folder in (".git", ".venv", "venv", "node_modules", "__pycache__", "target", "build", "dist"):
            self.put(f"{folder}/requirements.txt", "hidden==1\n")
        self.assertEqual(self.deps(), [])

    def test_generated_directories_do_not_add_copied_manifests(self):
        self.put("pom.xml", "<project><dependencies><dependency><groupId>real</groupId><artifactId>app</artifactId><version>1</version></dependency></dependencies></project>")
        self.put("target/classes/pom.xml", "<project><dependencies><dependency><groupId>generated</groupId><artifactId>copy</artifactId><version>9</version></dependency></dependencies></project>")
        self.put("build/copied/package.json", json.dumps({"dependencies": {"ghost": "1"}}))
        self.put("dist/copied/requirements.txt", "ghost-python==1\n")
        dependencies = self.deps()
        self.assertEqual([(item["name"], item["ecosystem"]) for item in dependencies], [("real:app", "Maven")])

    def test_31_empty_project(self):
        self.assertEqual(self.deps(), [])

    def test_32_duplicate_name_version_across_files(self):
        self.put("requirements.txt", "a==1\n")
        self.put("sub/requirements.txt", "A==1\n")
        self.assertEqual(len(self.deps("PyPI")), 1)

    def test_33_mixed_project(self):
        self.put("requirements.txt", "requests==2.0\n")
        self.package({"dependencies": {"left-pad": "1.0"}})
        self.assertEqual({d["ecosystem"] for d in self.deps()}, {"PyPI", "npm"})

    def test_34_exact_contract_fields(self):
        self.put("requirements.txt", "foo==1\n")
        self.assertEqual(set(self.deps()[0]), {"name", "version", "ecosystem", "source_file"})

    def test_35_requirement_multiple_constraints(self):
        self.put("requirements.txt", "foo>=1,<3\n")
        self.assertEqual(self.deps("PyPI")[0]["version"], "<3,>=1")

    # Maven and Gradle dependency extraction
    def test_36_namespaced_pom_and_property_resolution(self):
        self.put("pom.xml", """<project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion><properties><spring.version>6.1.2</spring.version></properties>
          <dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>${spring.version}</version></dependency></dependencies>
        </project>""")
        self.assertEqual(self.deps("Maven"), [{"name": "org.springframework:spring-core", "version": "6.1.2", "ecosystem": "Maven", "source_file": "pom.xml"}])

    def test_37_dependency_management_applies_only_to_declared_dependencies(self):
        self.put("pom.xml", """<project><dependencyManagement><dependencies>
          <dependency><groupId>org.example</groupId><artifactId>managed</artifactId><version>2.0</version></dependency>
          <dependency><groupId>org.example</groupId><artifactId>unused</artifactId><version>3.0</version></dependency>
        </dependencies></dependencyManagement><dependencies>
          <dependency><groupId>org.example</groupId><artifactId>managed</artifactId></dependency>
        </dependencies></project>""")
        self.assertEqual([(d["name"], d["version"]) for d in self.deps("Maven")], [("org.example:managed", "2.0")])

    def test_38_unresolved_pom_property_is_not_invented(self):
        self.put("pom.xml", "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${missing.version}</version></dependency></dependencies></project>")
        self.assertEqual(self.deps("Maven")[0]["version"], "${missing.version}")

    def test_39_pom_duplicate_coordinates_and_scope_policy(self):
        self.put("pom.xml", """<project><dependencies>
          <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version><scope>test</scope></dependency>
          <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version><scope>provided</scope></dependency>
          <dependency><groupId>g</groupId><artifactId>b</artifactId><version>2</version><scope>provided</scope></dependency>
        </dependencies></project>""")
        self.assertEqual({d["name"] for d in self.deps("Maven")}, {"g:a", "g:b"})

    def test_40_malformed_pom_is_ignored(self):
        self.put("pom.xml", "<project><dependencies>")
        self.assertEqual(self.deps("Maven"), [])

    def test_41_gradle_groovy_declarations_and_configurations(self):
        self.put("build.gradle", """dependencies {
          implementation 'g:impl:1.0'
          api("g:api:2.0")
          runtimeOnly 'g:runtime:3.0'
          compileOnly("g:compile:4.0")
          // implementation 'g:commented:1'
        }
        """)
        self.assertEqual({(d["name"], d["version"]) for d in self.deps("Maven")}, {
            ("g:impl", "1.0"), ("g:api", "2.0"), ("g:runtime", "3.0"), ("g:compile", "4.0")
        })

    def test_42_gradle_kotlin_declarations(self):
        self.put("build.gradle.kts", """dependencies {
          implementation("g:impl:1.0")
          api('g:api:2.0')
          compileOnly("g:compile:3.0")
        }
        """)
        self.assertEqual({d["name"] for d in self.deps("Maven")}, {"g:impl", "g:api", "g:compile"})

    def test_43_gradle_variable_and_dynamic_versions_are_conservative(self):
        self.put("build.gradle", """dependencies {
          implementation 'g:dynamic:1.+'
          implementation "g:property:${version}"
          implementation libs.catalogEntry
        }
        """)
        self.assertEqual({(d["name"], d["version"]) for d in self.deps("Maven")}, {
            ("g:dynamic", "1.+"), ("g:property", "${version}")
        })

    def test_44_gradle_lockfile_includes_transitive_and_overrides_declaration(self):
        self.put("build.gradle", "dependencies {\n implementation 'g:direct:1.0'\n}\n")
        self.put("gradle.lockfile", "g:direct:1.2=compileClasspath,runtimeClasspath\ng:transitive:4.0=runtimeClasspath\n")
        result = self.deps("Maven")
        self.assertEqual({(d["name"], d["version"]) for d in result}, {("g:direct", "1.2"), ("g:transitive", "4.0")})
        self.assertTrue(all(d["source_file"] == "gradle.lockfile" for d in result))

    def test_45_mixed_python_npm_and_maven_project(self):
        self.put("requirements.txt", "requests==2.0\n")
        self.package({"dependencies": {"left-pad": "1.0"}})
        self.put("pom.xml", "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency></dependencies></project>")
        self.assertEqual({d["ecosystem"] for d in self.deps()}, {"PyPI", "npm", "Maven"})

    def test_46_overlapping_maven_manifests_deduplicate_coordinate_version(self):
        self.put("pom.xml", "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency></dependencies></project>")
        self.put("build.gradle", "dependencies {\n implementation 'g:a:1'\n}\n")
        result = self.deps("Maven")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "g:a")


if __name__ == "__main__":
    unittest.main()
