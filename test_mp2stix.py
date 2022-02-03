import unittest
from malpedia_stix_export import *
from stix2 import Report, IntrusionSet, Relationship, Malware, Bundle
import uuid


class BrokerTest(unittest.TestCase):
    @staticmethod
    def test_tmp():
        report = Report(
            id="report--" + str(uuid.uuid4()),
            name="test_name",
            description="tests descr",
            object_refs=["malware--" + str(uuid.uuid4())],
            external_references=[
                {"source_name": "heise", "url": "http://www.heise.de"}
            ],
            labels=["threat-report"],
            published="1970-01-01T00:00:00Z",
            confidence=95,
        )
        print(report["name"])

    @staticmethod
    def test_build_reports():
        tests = [
            {
                "malware": {"id": "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"},
                "mp_obj": {"urls": ["http://example.com"]},
                "bundle": [
                    {
                        "type": "report",
                        "name": "name1",
                        "external_references": [
                            {"url": "http://example2.com", "source_name": "Example2"}
                        ],
                    },
                    {
                        "type": "report",
                        "name": "name2",
                        "external_references": [
                            {"url": "http://example3.com", "source_name": "Example3"}
                        ],
                    },
                ],
                "references": {
                    "http://example.com": {
                        "date": "01-10-2004",
                        "language": "English",
                        "organization": "Heise",
                        "title": "{Hallo}",
                    }
                },
            },
            {
                "malware": {"id": "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"},
                "mp_obj": {"urls": ["http://example.com"]},
                "bundle": [
                    {
                        "type": "report",
                        "name": "name1",
                        "external_references": [
                            {"url": "http://example.com", "source_name": "Example"}
                        ],
                    },
                    {
                        "type": "report",
                        "name": "name2",
                        "external_references": [
                            {"url": "http://example2.com", "source_name": "Example2"}
                        ],
                    },
                ],
                "references": {
                    "http://example.com": {
                        "date": "01-10-2004",
                        "language": "English",
                        "organization": "Heise",
                        "title": "{Hallo}",
                    }
                },
            },
        ]

        for test in tests:
            print("\nNEW TEST")
            bundle = []
            for report in test["bundle"]:
                bundle.append(
                    Report(
                        id="report--" + str(uuid.uuid4()),
                        name=report["name"],
                        description="tests descr",
                        object_refs=["indicator--" + str(uuid.uuid4())],
                        external_references=report["external_references"],
                        labels=["threat-report"],
                        published="1970-01-01T00:00:00Z",
                        confidence=95,
                    )
                )
            print("PRE BUNDLE")
            for o in bundle:
                print(o["id"])
            result = build_reports(
                test["malware"], test["mp_obj"], bundle, test["references"]
            )
            print("\nPOST BUNDLE")
            for r in result:
                print(r)

    @staticmethod
    def test_add_object_ref():
        tests = [
            {
                "obj_ref_lists": [
                    [
                        "indicator--945e1938-5605-44c9-a272-213728e1826f",
                        "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7",
                    ],
                    [
                        "indicator--945e1938-5605-44c9-a272-213728e1826f",
                        "malware--a9f5d9b5-5f13-415e-8f15-e54f2e64da72",
                    ],
                ],
                "malware": {"id": "malware--8f20728a-7e18-4f46-b8e0-0e3d0eebb4d7"},
            }
        ]

        for test in tests:
            reports = []
            for ref_list in test["obj_ref_lists"]:
                reports.append(
                    Report(
                        id="report--" + str(uuid.uuid4()),
                        name="test_name",
                        description="tests descr",
                        object_refs=ref_list,
                        external_references=[
                            {"source_name": "heise", "url": "http://www.heise.de"}
                        ],
                        labels=["threat-report"],
                        published="1970-01-01T00:00:00Z",
                        confidence=95,
                    )
                )
            result = add_object_ref(reports, test["malware"])
            for r in result:
                print("\n", r)

    @staticmethod
    def test_compile_report():
        tests = [
            {
                "url": "http://example.com",
                "references": {
                    "http://example.com": {
                        "date": "01-10-2004",
                        "language": "English",
                        "organization": "Heise",
                        "title": "{Hallo}",
                    }
                },
                "malware": {"id": "malware--" + str(uuid.uuid4())},
            }
        ]

        for test in tests:
            result = compile_report(test["url"], test["references"], test["malware"])
            print(result)

    @staticmethod
    def test_disambiguate_report_names():
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
            print("\n", result)
