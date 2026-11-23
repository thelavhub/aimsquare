"""PDF -> table rows for AIMsquare. Text layer first; OCR fallback for image-only pages."""
import io, re
import pdfplumber

NUM = re.compile(r'^\(?-?\d[\d,]*\.?\d*\)?%?$')
LEAD = re.compile(r'^(?:(?:\d{1,2}|[IVXivx]{1,5}|\([ivxa-zA-Z]{1,5}\)|[a-zA-Z]\))[\.\)]?\s+)+')


def words_to_rows(words):
    """words: dicts with text, x0, x1, top, bottom. Returns [[label, num, num...], ...]."""
    ws = sorted(words, key=lambda w: (w["top"], w["x0"]))
    lines = []
    for w in ws:
        h = max(w["bottom"] - w["top"], 1)
        tol = max(2, h * 0.45)
        if lines and abs(lines[-1]["y"] - w["top"]) <= tol:
            lines[-1]["items"].append(w)
        else:
            lines.append({"y": w["top"], "items": [w]})
    rows = []
    for L in lines:
        L["items"].sort(key=lambda w: w["x0"])
        cells = []
        for w in L["items"]:
            h = max(w["bottom"] - w["top"], 1)
            if cells and (w["x0"] - cells[-1]["x1"]) < max(3, h * 0.5):
                cells[-1]["s"] += " " + w["text"]
                cells[-1]["x1"] = w["x1"]
            else:
                cells.append({"s": w["text"], "x1": w["x1"]})
        label, nums, started = [], [], False
        for c in cells:
            t = re.sub(r"\s+", " ", c["s"]).strip()
            if not t:
                continue
            t = re.sub(r"\(\s+", "(", t)
            t = re.sub(r"\s+\)", ")", t)
            t = re.sub(r"^[\u20b9`]\s?", "", t)
            if t in ("-", "\u2013", "\u2014"):
                if label:
                    nums.append("0"); started = True
                continue
            if NUM.match(t.replace(" ", "")):
                nums.append(t.replace(" ", "")); started = True
            elif not started:
                label.append(t)
            else:  # text after numbers: not a clean table row
                label.append(t); nums = []; started = False
        lab = LEAD.sub("", " ".join(label)).strip()
        if not lab or not nums:
            continue
        if len(lab) > 90 or len(lab.split()) > 14:
            continue
        if re.match(r"^(page|integrated annual report|annexure)", lab, re.I):
            continue
        if len(nums) >= 3 and re.fullmatch(r"\d{1,2}", nums[0]) and re.search(r"[,.]|\d{3,}", nums[1]):
            nums.pop(0)  # drop a leading "Note" reference column
        rows.append([lab] + nums)
    return rows


def _ocr_words(page, dpi=200):
    import pytesseract
    img = page.to_image(resolution=dpi).original
    d = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT, config="--psm 6")
    k = 72.0 / dpi
    out = []
    for i, t in enumerate(d["text"]):
        t = (t or "").strip()
        try:
            conf = float(d["conf"][i])
        except Exception:
            conf = -1
        t = t.strip("|}]{[")
        if re.fullmatch(r"\(?\d{1,3}\.\d{3}\)?", t):  # OCR reads "20,211" as "20.211"
            t = t.replace(".", ",")
        if not t or conf < 30:
            continue
        x0, top = d["left"][i] * k, d["top"][i] * k
        out.append({"text": t, "x0": x0, "x1": x0 + d["width"][i] * k, "top": top, "bottom": top + d["height"][i] * k})
    return out


def pdf_to_rows(data: bytes, ocr=True, max_pages=400):
    rows, ocr_pages, total = [], 0, 0
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        total = len(pdf.pages)
        for page in pdf.pages[:max_pages]:
            words = page.extract_words(x_tolerance=2, y_tolerance=2)
            image_only = len(words) < 3 or (len(words) < 40 and len(page.images) > 0)
            if ocr and image_only:
                try:
                    ow = _ocr_words(page)
                    if len(ow) > len(words):
                        words = ow; ocr_pages += 1
                except Exception:
                    pass
            rows.extend(words_to_rows(words))
            try: page.flush_cache()
            except Exception: pass
    return rows, {"pages": total, "ocr_pages": ocr_pages, "row_count": len(rows)}
