import unittest
from mp2stix import *
from tempfile import TemporaryDirectory
from stix2 import Report, IntrusionSet, Relationship, Malware, Bundle
import stix2
import uuid


class BrokerTest(unittest.TestCase):

    def setUp(self):
        self.tmpdir = TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_disambiguate_aliases(self):
        tests = [
            {
                "misp": {"values": [{"meta": {"synonyms": ["name1", "name2"]}}, {"meta": {"synonyms": ["name1", "name3"]}}]},
                "result": {"values": [{"meta": {"synonyms": ["name2"]}}, {"meta": {"synonyms": ["name3"]}}]}
            },
            {
                "misp": {"values": [{"meta": {"synonyms": ["name1", "name2"]}}, {"meta": {"synonyms": ["name3", "name4"]}}]},
                "result": {"values": [{"meta": {"synonyms": ["name1", "name2"]}}, {"meta": {"synonyms": ["name3", "name4"]}}]}
            }

        ]
        
        for test in tests:
            result = disambiguate_aliases(test["misp"])
            self.assertEqual(result, test["result"])

    def test_build_bundle(self):
        tests = [
            {
                "families": {},
                "misp": {},
                "references": {},
                "result": [{"type": "identity", "name": 'Malpedia (Fraunhofer FKIE)', "identity_class": "organization", "class": "stix2.v21.sdo.Identity"}]
            }
        ]

        for test in tests:
            result = build_bundle(test["families"], test["misp"], test["references"])
            for obj in test["result"]:
                keys = {k for k in obj if k != "class"}
                self.assertTrue([o for o in result
                                 if {key: o[key] for key in o if key in keys} == {key: obj[key] for key in obj if key in keys}
                                 and isinstance(o, stix2.v21.sdo.Identity)])

    def test_integrate_new_objs(self):
        tests = [
            {
                "new_objs": [{"id": "id1"}, {"id": "id2"}],
                "bundle": [{"id": "id2"}, {"id": "id3"}],
                "results": [{"id": "id1"}, {"id": "id2"}, {"id": "id3"}]
            }
        ]

        for test in tests:
            result = integrate_new_objs(test["new_objs"], test["bundle"])
            for obj in result: self.assertIn(obj, test["results"])
            for obj in test["results"]: self.assertIn(obj, result)

    def test_build_malware(self):
        tests = [{
            "name_key": "Malware1",
            "obj": {"updated": "1.1.1970", "description": "<Malware1 description>", "alt_names": ["MW1"], "common_name": "Malware1"},
            "result": {'type': 'malware', 'spec_version': '2.1', 'created_by_ref': MALPEDIA_IDENTITY, 'created': '1970-01-01 00:00:00', 'modified': '1970-01-01 00:00:00', 'name': 'Malware1', 'description': '<Malware1 description>\nThis Malware object was created based on information from https://malpedia.caad.fkie.fraunhofer.de/details/Malware1. Last update: 1.1.1970.', 'is_family': 'True', 'aliases': "['MW1', 'Malware1']", 'revoked': 'False', 'labels': "['malware']", 'confidence': '95'}
        }]

        for test in tests:
            result = build_malware(test["name_key"], test["obj"])
            self.assertTrue(isinstance(result, stix2.v21.sdo.Malware))
            self.assertTrue(result["id"].startswith("malware--"))
            result_dict = {k: str(result[k]) for k in result if k != "id"}
            self.assertEqual(result_dict, test["result"])

    def test_build_intrusion_sets(self):
        tests = [
            {
                "malware": {"attribution": {"attacker1", "attacker2"}},
                "misp": {"values": {}},
                "bundle": [{"type": "intrusion-set", "name": "Attacker2"}],
                "result": [{"name": "Attacker2", "type": "intrusion-set"}, {"name": "attacker1", "type": "intrusion-set"}]
            }
        ]

        for test in tests:
            result = build_intrusion_sets(test["malware"], test["misp"], test["bundle"])
            result = [{"name": obj["name"], "type": obj["type"]} for obj in result]
            for obj in result: self.assertIn(obj, test["result"])
            for obj in test["result"]: self.assertIn(obj, result)

    def test_compile_intrusion_set(self):
        tests = [
            {
                "misp": {"values": [{"value": "name1", "meta": {"synonyms": ["name1a"]}, "descritpion": "<descritpion>"}, {"value": "name2"}]},
                "actor": "Name1",
                "result": {'type': 'intrusion-set', 'spec_version': '2.1', 'created_by_ref': MALPEDIA_IDENTITY, 'created': '2022-02-04 09:37:25.338005+00:00', 'modified': '2022-02-04 09:37:25.338005+00:00', 'name': 'Name1', 'description': 'This Intrusion-Set object was created based on information from https://malpedia.caad.fkie.fraunhofer.de and https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json.', 'aliases': ['name1a'], 'revoked': False, 'confidence': 95}
            }
        ]

        for test in tests:
            result = compile_intrusion_set(test["misp"], test["actor"])
            result_dict = {k: result[k] for k in result if k != "id" and not isinstance(result[k], stix2.utils.STIXdatetime)}
            exp_result_dict = {k: test["result"][k] for k in result_dict}
            self.assertEqual(result_dict, exp_result_dict)

    def test_build_relationships(self):
        tests = [
            {
                "malware": {"id": "malware--11111111-1111-1111-a111-111111111111"},
                "intrusion-sets": [{"id": "intrusion-set--11111111-1111-1111-b111-111111111111"}],
                "mp_obj": {"updated": "1.1.1970"},
                "result": [{"source_ref": "intrusion-set--11111111-1111-1111-b111-111111111111", "target_ref": "malware--11111111-1111-1111-a111-111111111111", "relationship_type": "uses"}]
            }
        ]

        for test in tests:
            result = build_relationships(test["malware"], test["intrusion-sets"], test["mp_obj"])
            for rel in result:
                rel_dict = {key: rel[key] for key in rel if key in {"target_ref", "source_ref", "relationship_type"}}
                self.assertIn(rel_dict, test["result"])
                self.assertTrue(isinstance(rel, stix2.v21.sro.Relationship))

    def test_build_reports(self):
        tests = [
            {
                "malware": {"id": "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"},
                "mp_obj": {"urls": ["http://example.com"]},
                "bundle": [
                    Report(
                        id="report--" + str(uuid.uuid4()),
                        name="name1",
                        description="tests descr",
                        object_refs=["indicator--" + str(uuid.uuid4())],
                        external_references=[{"url": "http://example.com", "source_name": "Example"}],
                        labels=["threat-report"],
                        published="1970-01-01T00:00:00Z",
                        confidence=95,
                    ),
                    Report(
                        id="report--" + str(uuid.uuid4()),
                        name="name2",
                        description="tests descr",
                        object_refs=["indicator--" + str(uuid.uuid4())],
                        external_references=[{"url": "http://example2.com", "source_name": "Example2"}],
                        labels=["threat-report"],
                        published="1970-01-01T00:00:00Z",
                        confidence=95,
                    )
                ],
                "references": {
                    "http://example.com": {
                        "date": "01-10-2004",
                        "language": "English",
                        "organization": "Heise",
                        "title": "{Hallo}",
                    }
                },
                "result": [{"type": "report", "spec_version": "2.1", "name": "name1", "description": "tests descr", "published": "1970-01-01T00:00:00Z", "object_refs": ["indicator--c623c031-b7e7-4892-a88d-9d5752096b88", "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"], "labels": ["threat-report"], "confidence": 95, "external_references": [{"source_name": "Example", "url": "http://example.com"}]}]
            },
            {
                "malware": {"id": "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"},
                "mp_obj": {"urls": ["http://example.com"]},
                "bundle": [
                    Report(
                        id="report--" + str(uuid.uuid4()),
                        name="name1",
                        description="tests descr",
                        object_refs=["indicator--" + str(uuid.uuid4())],
                        external_references=[{"url": "http://example.com", "source_name": "Example"}],
                        labels=["threat-report"],
                        published="1970-01-01T00:00:00Z",
                        confidence=95,
                    ),
                    Report(
                        id="report--" + str(uuid.uuid4()),
                        name="name2",
                        description="tests descr",
                        object_refs=["indicator--" + str(uuid.uuid4())],
                        external_references=[{"url": "http://example2.com", "source_name": "Example2"}],
                        labels=["threat-report"],
                        published="1970-01-01T00:00:00Z",
                        confidence=95,
                    )
                ],
                "references": {
                    "http://example.com": {
                        "date": "01-10-2004",
                        "language": "English",
                        "organization": "Heise",
                        "title": "{Hallo}",
                    }
                },
                "result": [{"type": "report", "spec_version": "2.1", "name": "name1", "description": "tests descr", "published": "1970-01-01T00:00:00Z", "object_refs": ["indicator--aba91e30-94ff-40ee-af60-4e4aebd6b91e", "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"], "labels": ["threat-report"], "confidence": 95, "external_references": [{"source_name": "Example", "url": "http://example.com"}]}]
            },
        ]

        for test in tests:
            result = build_reports(
                test["malware"], test["mp_obj"], test["bundle"], test["references"]
            )
            for obj in test["result"]:
               self.assertTrue([o for o in result if [o[key] == obj[key] for key in obj]])

    def test_add_object_ref(self):
        tests = [
            {
                "obj_ref_list": [
                    "indicator--945e1938-5605-44c9-a272-213728e1826f",
                    "malware--a9f5d9b5-5f13-415e-8f15-e54f2e64da72",
                ],
                "malware": {"id": "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"},
                "result": [{"indicator--945e1938-5605-44c9-a272-213728e1826f", "malware--a9f5d9b5-5f13-415e-8f15-e54f2e64da72", "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"}]
            },
            {
                "obj_ref_list": [
                    "indicator--945e1938-5605-44c9-a272-213728e1826f",
                    "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7",
                ],
                "malware": {"id": "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"},
                "result": [{"indicator--945e1938-5605-44c9-a272-213728e1826f", "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"}]
            }
        ]

        for test in tests:
            reports = [
                    Report(
                        id="report--" + str(uuid.uuid4()),
                        name="test_name",
                        description="tests descr",
                        object_refs=test["obj_ref_list"],
                        external_references=[
                            {"source_name": "heise", "url": "http://www.heise.de"}
                        ],
                        labels=["threat-report"],
                        published="1970-01-01T00:00:00Z",
                        confidence=95,
                    )
                ]
            result = add_object_ref(reports, test["malware"])
            for report in result:
                self.assertIn(set(report["object_refs"]), test["result"])

    def test_compile_report(self):
        tests = [
            {
                "url": "http://example.com",
                "references": {
                    "http://example.com": {
                        "date": "01-10-2004",
                        "language": "English",
                        "organization": "Heise",
                        "title": "{Name1}",
                    }
                },
                "malware": [{"id": "malware--11111111-1111-1111-a111-111111111111"}],
                "result": {"type": "report", "spec_version": "2.1", "created_by_ref": MALPEDIA_IDENTITY, "name": "Name1", "description": "Language: English\nOrganization: Heise", "object_refs": ["malware--11111111-1111-1111-a111-111111111111"], "labels": ["threat-report"], "confidence": 95, "external_references": "[ExternalReference(source_name='Name1', url='http://example.com')]"}
            }
        ]

        for test in tests:
            result = compile_report(test["url"], test["references"], test["malware"])
            for key in {"created", "modified", "published"}: self.assertTrue(result[key], stix2.utils.STIXdatetime)
            result_dict = {key: str(result[key]) for key in test["result"]}
            for key in test["result"]: self.assertEqual(str(test["result"][key]), result_dict[key])

    def test_get_date_from_html(self):
        tests = [
            {
                "html": "<date>1.1.1970</date>",
                "result": "1970-01-01T00:00:00Z"
            }
        ]

        for test in tests:
            result = get_date_from_html(test["html"])
            self.assertEqual(result, test["result"])

    def test_find_date_elements(self):
        tests = [
            {
                "html": "...<time>1.1.1970</time>...",
                "result": ["<time>1.1.1970</time>"]
            },
            {
                "html": "...<span class='header'>1.1.1970</span>...",
                "result": ['<span class="header">1.1.1970</span>']
            },
            {
                "html": "...<span id='meta'>1.1.1970</span>...",
                "result": ['<span id="meta">1.1.1970</span>']
            },
            {
                "html": "...<span item_prop='dateCreated'>1.1.1970</span>...",
                "result": ['<span item_prop="dateCreated">1.1.1970</span>']
            },
            {
                "html": "...<span datetime='1.1.1970'>Word</span>...",
                "result": ['<span datetime="1.1.1970">Word</span>']
            },
            {
                "html": "...<body datetime='1.1.1970'>Word</body>...",
                "result": []
            },
            {
                "html": "...<span class=comment><span datetime='1.1.1970'>Word</span></span>...",
                "result": []
            },
            {
                "html": "...<history><span datetime='1.1.1970'>Word</span></history>...",
                "result": []
            },
            {
                "html": "...<related datetime='1.1.1970'>Word</related>...",
                "result": []
            },
        ]

        for test in tests:
            result = find_date_elements(test["html"])
            for obj in result: self.assertIn(str(obj), test["result"])
            for obj in test["result"]: self.assertIn(obj, [str(o) for o in result])

    def test_disambiguate_report_names(self):
        tests = [
            {
                "new_report": {"name": "name1"},
                "bundle": [
                    {"type": "report", "name": "name1"},
                    {"type": "report", "name": "name2"},
                ],
                "reports": [
                    {"type": "report", "name": "name3"},
                    {"type": "report", "name": "name4"},
                ],
                "result_name": "name1 (1)"
            },
            {
                "new_report": {"name": "name5"},
                "bundle": [
                    {"type": "report", "name": "name1"},
                    {"type": "report", "name": "name2"},
                ],
                "reports": [
                    {"type": "report", "name": "name3"},
                    {"type": "report", "name": "name4"},
                ],
                "result_name": "name5"
            },
        ]

        for test in tests:
            report = Report(
                type="report",
                id="report--" + str(uuid.uuid4()),
                name=test["new_report"]["name"],
                description="tests descr",
                object_refs=["indicator--" + str(uuid.uuid4())],
                external_references=[
                    {"source_name": "heise", "url": "http://www.heise.de"}
                ],
                labels=["threat-report"],
                published="1970-01-01T00:00:00Z",
                confidence=95,
            )

            result = disambiguate_report_names(report, test["bundle"], test["reports"])
            self.assertTrue(isinstance(result, stix2.v21.sdo.Report))
            self.assertEqual(result["name"], test["result_name"])