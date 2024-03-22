import pathlib
import json


def get_cordova_metadata(js_file: str, is_text=False) -> dict:
    """Parses the given JavaScript-File that contains Cordova-Dependencies.

    :param js_file: the javascript content or file path
    :type js_file: str
    :param is_text: indicates whether the fiven js_file param should be
                    treated as text content, defaults to False
    :type is_text: bool, optional
    :return: the cordova dependencies in a dict
    :rtype: dict
    """
    content = None
    if is_text:
        if isinstance(js_file, bytes):
            content = js_file.decode("utf-8").splitlines()
        else:
            content = js_file.splitlines()

    if not content and not is_text:
        path = pathlib.Path(js_file)
        if path.exists():
            try:
                with open(str(path), "r") as fp:
                    content = fp.readlines()
            except OSError:
                pass

    if content:
        in_metadata = False
        json_content = ""
        for line in content:
            line = line.strip()
            if (
                "// TOP OF METADATA" in line or "module.exports.metadata" in line
            ) and not in_metadata:
                in_metadata = True
                json_content += "{"
                continue
            elif "// BOTTOM OF METADATA" in line or "};" in line:
                json_content += "}"
                break

            if in_metadata and "//" not in line and line[0] != "{":
                json_content += line
        try:
            return json.loads(json_content) if json_content else {}
        except json.JSONDecodeError:
            pass  # maybe let that exception through
    return {}
