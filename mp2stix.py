import requests, json, uuid, re, html
import parsedatetime
import bibtexparser
from bs4 import BeautifulSoup
from datetime import datetime, date
from stix2 import Report, IntrusionSet, Relationship, Malware, Bundle


URL_FAMILIES = "https://malpedia.caad.fkie.fraunhofer.de/api/get/families"
URL_BIBTEX = "https://malpedia.caad.fkie.fraunhofer.de/api/get/bib"
URL_MISP = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
)
URL_MALPEDIA = "https://malpedia.caad.fkie.fraunhofer.de"


# BUILD STIX BUNDLE #


def get_malpedia_stix():
    print("Accessing necessesary sources...")
    bibtex_parser = bibtexparser.bparser.BibTexParser()
    bibtex_parser.ignore_nonstandard_types = False
    references = {
        o["url"]: o
        for o in bibtexparser.loads(
            requests.get(URL_BIBTEX).content, bibtex_parser
        ).entries
    }
    families = requests.get(URL_FAMILIES).json()
    misp = disambiguate_aliases(requests.get(URL_MISP).json())
    print("Building stix objects (may take some minutes)...")
    bundle = build_bundle(families, misp, references)
    print("Building json bundle...")
    json_bundle = json.loads(Bundle(*bundle).serialize())
    return json_bundle


def disambiguate_aliases(misp):
    objs_with_aliases = [
        obj for obj in misp["values"] if "meta" in obj and "synonyms" in obj["meta"]
    ]
    aliases = [
        name.lower() for obj in objs_with_aliases for name in obj["meta"]["synonyms"]
    ]
    for obj in objs_with_aliases:
        obj["meta"]["synonyms"] = [
            name for name in obj["meta"]["synonyms"] if aliases.count(name.lower()) == 1
        ]
    return misp


def build_bundle(families, misp, references):
    bundle = []
    for key in families:
        malware = build_malware(key, families[key], bundle)
        intrusion_sets = build_intrusion_sets(families[key], misp, bundle)
        relationships = build_relationships(malware, intrusion_sets, families[key])
        reports = build_reports(malware, families[key], bundle, references)
        bundle = integrate_new_objs(
            [malware] + intrusion_sets + relationships + reports, bundle
        )
    malp_report = compile_report(
        URL_MALPEDIA,
        {
            URL_MALPEDIA: {
                "date": str(datetime.now()),
                "title": "Malpedia",
                "organization": "Fraunhofer FKIE",
                "language": "englisch",
            }
        },
        [obj for obj in bundle if obj["type"] != "report"],
    )
    bundle.append(malp_report)
    return bundle


def integrate_new_objs(new_objs, bundle):
    ids = {obj["id"] for obj in bundle}
    for new_obj in new_objs:
        if new_obj["id"] in ids:
            bundle.remove([o for o in bundle if o["id"] == new_obj["id"]][0])
        bundle.append(new_obj)
        ids.add(new_obj["id"])
    return bundle


# BUILD MALWARE #


def build_malware(key, obj, bundle):
    malpedia_link = URL_MALPEDIA + "/details/" + key
    description = (
        "This Malware object was created based on information from "
        + malpedia_link
        + "."
    )
    if obj["updated"]:
        description += " Last update: " + obj["updated"] + "."
    if obj["description"]:
        description = obj["description"] + "\n" + description
    malware = Malware(
        id="malware--" + str(uuid.uuid4()),
        aliases=obj["alt_names"] + [obj["common_name"]],
        type="malware",
        name=key,
        labels=["malware"],
        description=description,
        is_family=True,
        confidence=95,
    )
    return malware


# BUILD INTRUSION SETS #


def build_intrusion_sets(malware, misp, bundle):
    intrusion_sets = []
    for iset in malware["attribution"]:
        existing_objs = [
            obj
            for obj in bundle
            if obj["type"] == "intrusion-set" and obj["name"].lower() == iset.lower()
        ]
        if existing_objs:
            intrusion_sets.extend(existing_objs)
        else:
            intrusion_sets.append(compile_intrusion_set(misp, iset))
    return intrusion_sets


def compile_intrusion_set(misp, actor):
    misp_objs = [obj for obj in misp["values"] if obj["value"].lower() == actor.lower()]
    aliases = [
        obj["meta"]["synonyms"]
        for obj in misp_objs
        if "meta" in obj and "synonyms" in obj["meta"]
    ]
    aliases = aliases[0] if aliases else []
    descriptions = [obj["description"] for obj in misp_objs if "description" in obj]
    description = (
        "This Intrusion-Set object was created based on information from "
        + URL_MALPEDIA
        + " and "
        + URL_MISP
        + "."
    )
    if descriptions:
        description = descriptions[0] + "\n" + description
    intrusion_set = IntrusionSet(
        id="intrusion-set--" + str(uuid.uuid4()),
        type="intrusion-set",
        name=actor,
        description=description,
        aliases=aliases,
        confidence=95,
    )
    return intrusion_set


# BUILD RELATIONSHIPS #


def build_relationships(malware, intrusion_sets, obj):
    description = "Relationship stated on " + URL_MALPEDIA
    if obj["updated"]:
        description += ". Last update: " + obj["updated"] + "."
    rels = []
    for intrusion_set in intrusion_sets:
        rels.append(
            Relationship(
                id="relationship--" + str(uuid.uuid4()),
                type="relationship",
                relationship_type="uses",
                source_ref=intrusion_set["id"],
                target_ref=malware["id"],
                description=description,
                confidence=95,
            )
        )
    return rels


# BUILD REPORTS #


def build_reports(malware, mp_obj, bundle, references):
    new_reports = []
    for url in mp_obj["urls"]:
        existing_objs = [
            stix_obj
            for stix_obj in bundle + new_reports
            if stix_obj["type"] == "report"
            and url in str(stix_obj["external_references"])
        ]
        if existing_objs:
            new_reports.extend(add_object_ref(existing_objs, malware))
        else:
            new_reports.append(
                disambiguate_report_names(
                    compile_report(url, references, [malware]), bundle, new_reports
                )
            )
    return new_reports


def add_object_ref(report_objs, malware):
    enriched_reports = []
    for stix_obj in report_objs:
        enriched_reports.append(
            stix_obj.new_version(
                object_refs=list(set(stix_obj["object_refs"] + [malware["id"]]))
            )
        )
    return enriched_reports


def compile_report(url, references, contained_objs):
    description = ""
    if url in references.keys():
        date = parse_date(references[url]["date"])
        title = re.search(r"\{?(.*)(?<!})", references[url]["title"]).group(1)
        if "language" in references[url]:
            description += "Language: " + references[url]["language"] + "\n"
        if "organization" in references[url]:
            description += "Organization: " + references[url]["organization"]
        if description.endswith("\n"):
            description = description[:-1]
    else:
        date, title = get_alt_meta(url)
    report = Report(
        type="report",
        id="report--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, url)),
        name=title.strip(),
        description=description,
        external_references=[{"source_name": title, "url": url}],
        object_refs=[obj["id"] for obj in contained_objs],
        labels=["threat-report"],
        published=date,
        confidence=95,
    )
    return report


def parse_date(string):
    time_struct, parse_status = parsedatetime.Calendar().parse(string)
    time = datetime(*time_struct[:6])
    return time


def get_alt_meta(url):
    try:
        request = requests.get(url)
    except:
        request = None
    if request and request.status_code < 400 and not url.endswith(".pdf"):
        date = get_date_from_html(request.content)
        title_match = re.search(r"<title>(.*?)</title>", request.text, re.DOTALL)
        title = (
            html.unescape(title_match.group(1).replace("\n", " "))[:500]
            if title_match and len(title_match.group(1)) > 3
            else url
        )
    else:
        date = "1970-01-01T00:00:00Z"
        title_match = re.search(r".*/(.+?)\.[a-z]{2,4}$", url)
        title = (
            title_match.group(1)
            if title_match and len(title_match.group(1)) > 3
            else url
        )
    return date, title


def get_date_from_html(html):
    html_elements = find_date_elements(html)
    len(html_elements)
    for html_element in html_elements:
        time = parse_date(html_element.text)
        if time.date() < date.today():
            return time.strftime("%Y-%m-%dT%H:%M:%SZ")
    return "1970-01-01T00:00:00Z"


def find_date_elements(html):
    soup = BeautifulSoup(html, features="lxml")
    html_elements = soup.find_all(name=["time"])
    html_elements.extend(
        soup.find_all(
            class_=re.compile(
                r".*(?:meta|published|time|date|header|heading|created|av b aw ax bt|card).*"
            )
        )
    )
    html_elements.extend(
        soup.find_all(id=re.compile(r".*(?:authorposton|footer-info-lastmod|meta).*"))
    )
    html_elements.extend(
        soup.find_all(item_prop=re.compile(r".*(?:datePublished|dateCreated).*"))
    )
    html_elements.extend(soup.find_all(datetime_arg=re.compile(r".+")))
    html_elements.extend(soup.find_all(datetime=re.compile(r".+")))
    html_elements.extend(
        [
            t.parent
            for t in soup.find_all(
                string=lambda t: t
                and re.search(r'posted|published|edited|<span class="date">', t)
                and "\n" not in t
            )
        ]
    )
    for element in html_elements.copy():
        if element.name == "body":
            html_elements.remove(element)
        elif element.find_parent(
            class_=re.compile(
                r".*(?:revision|comment|sidebar(?!s)|preview|related|footer|referenc).*"
            ),
            name=re.compile(r"^(?!body).*"),
        ):
            html_elements.remove(element)
        elif element.find_parent(name=re.compile(r".*(?:aside|revision|history).*")):
            html_elements.remove(element)
        elif [w for w in ["related"] if w in element.name]:
            html_elements.remove(element)
    html_elements.sort(key=lambda x: len(x.text))
    return html_elements


def disambiguate_report_names(new_report, bundle, reports):
    existing_report_names = {
        stix_obj["name"]
        for stix_obj in bundle + reports
        if stix_obj["type"] == "report"
        and stix_obj["name"].startswith(new_report["name"])
    }
    if existing_report_names:
        numbers = {
            int(re.findall(r"\(([0-9]+)\)$", name)[0])
            for name in existing_report_names
            if re.findall(r"\(([0-9]+)\)$", name)
        }
        if numbers:
            new_name = new_report["name"] + " (" + str(max(numbers) + 1) + ")"
        else:
            new_name = new_report["name"] + " (1)"
        new_report = new_report.new_version(name=new_name)
    return new_report


# MAIN #


def main():
    stix = get_malpedia_stix()
    with open("./bundle.json", "w") as f:
        json.dump(stix, f, indent=4)


if __name__ == "__main__":
    main()
