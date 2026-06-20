"""
Generation de rapports PDF - CyberScan
Cree un rapport de diagnostic professionnel et telechargeable.
"""

import io
import os
import random
import string
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image,
)
from reportlab.pdfgen import canvas as pdfcanvas

# ---------------------------------------------------------------------------
# Couleurs
# ---------------------------------------------------------------------------
COLOR_PRIMARY       = HexColor("#1E3A5F")
COLOR_EMERALD       = HexColor("#10B981")
COLOR_LIGHT_BG      = HexColor("#F3F4F6")
COLOR_GRAY          = HexColor("#6B7280")
COLOR_LIGHT_GRAY    = HexColor("#9CA3AF")
COLOR_GRID          = HexColor("#E5E7EB")
COLOR_WHITE         = HexColor("#FFFFFF")
COLOR_BLACK         = HexColor("#111827")
COLOR_DARK          = HexColor("#0D1B2A")
COLOR_CRITICAL      = HexColor("#DC2626")
COLOR_HIGH          = HexColor("#EA580C")
COLOR_MEDIUM        = HexColor("#D97706")
COLOR_LOW           = HexColor("#16A34A")
COLOR_INFO          = HexColor("#0284C7")

SEVERITY_COLORS = {
    "critical": COLOR_CRITICAL, "high": COLOR_HIGH,
    "medium": COLOR_MEDIUM, "low": COLOR_LOW,
    "info": COLOR_INFO, "warning": COLOR_MEDIUM, "error": COLOR_CRITICAL,
}
SEVERITY_LABELS = {
    "critical": "CRITIQUE", "high": "ÉLEVÉE", "medium": "MOYENNE",
    "low": "FAIBLE", "info": "INFO", "warning": "ATTENTION", "error": "ERREUR",
}

LOGO_PATH = os.path.join(os.path.dirname(__file__), "..", "static", "img", "logo.png")

MODULES_NAMES = {
    "network": "Diagnostic réseau",
    "web":     "Diagnostic web & API",
    "infra":   "Diagnostic infrastructure",
    "pentest": "Pentest interne",
}


def generate_reference_code():
    """Genere un code de reference aleatoire a 8 caracteres alphanumeriques."""
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choices(chars, k=8))


def get_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CoverTitle", fontName="Helvetica-Bold", fontSize=26,
        textColor=COLOR_PRIMARY, alignment=TA_CENTER, spaceAfter=4*mm,
    ))
    styles.add(ParagraphStyle(
        name="CoverSubtitle", fontName="Helvetica", fontSize=13,
        textColor=COLOR_EMERALD, alignment=TA_CENTER, spaceAfter=3*mm,
    ))
    styles.add(ParagraphStyle(
        name="CoverInfo", fontName="Helvetica", fontSize=10,
        textColor=COLOR_GRAY, alignment=TA_CENTER, spaceAfter=2*mm,
    ))
    styles.add(ParagraphStyle(
        name="SectionTitle", fontName="Helvetica-Bold", fontSize=15,
        textColor=COLOR_PRIMARY, spaceBefore=7*mm, spaceAfter=4*mm,
    ))
    styles.add(ParagraphStyle(
        name="SubsectionTitle", fontName="Helvetica-Bold", fontSize=11,
        textColor=COLOR_EMERALD, spaceBefore=5*mm, spaceAfter=3*mm,
    ))
    styles.add(ParagraphStyle(
        name="BodyText2", fontName="Helvetica", fontSize=10,
        textColor=COLOR_BLACK, alignment=TA_JUSTIFY,
        spaceAfter=3*mm, leading=14,
    ))
    styles.add(ParagraphStyle(
        name="Disclaimer", fontName="Helvetica-Oblique", fontSize=8,
        textColor=COLOR_GRAY, alignment=TA_JUSTIFY,
        spaceAfter=2*mm, leading=11,
    ))
    styles.add(ParagraphStyle(
        name="LegalTitle", fontName="Helvetica-Bold", fontSize=11,
        textColor=COLOR_PRIMARY, spaceBefore=4*mm, spaceAfter=2*mm,
    ))
    styles.add(ParagraphStyle(
        name="LegalBody", fontName="Helvetica", fontSize=9,
        textColor=COLOR_BLACK, alignment=TA_JUSTIFY,
        spaceAfter=2*mm, leading=12.5,
    ))
    styles.add(ParagraphStyle(
        name="LegalBullet", fontName="Helvetica", fontSize=9,
        textColor=COLOR_BLACK, alignment=TA_JUSTIFY,
        spaceAfter=1.5*mm, leading=12.5, leftIndent=4*mm,
    ))
    return styles


def count_severities(results):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for mod_data in results.get("modules", {}).values():
        for f in mod_data.get("findings", []):
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
            elif sev in ("warning", "error"):
                counts["medium"] += 1
    return counts


# ---------------------------------------------------------------------------
# PAGE 1 : page de garde dessinee entierement au canvas (reproduit le visuel)
# ---------------------------------------------------------------------------
COVER_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "..", "static", "img", "cover_template.png")

# Fractions (x/width, y/height depuis le HAUT de l'image) mesurees sur le gabarit fourni
COVER_LABEL_Y_FRAC = 0.6621   # ligne des libelles CLIENT / DATE / REFERENCE
COVER_LINE_Y_FRAC  = 0.6946   # ligne de soulignement (valeurs posees juste au-dessus)
COVER_CLIENT_X_FRAC    = 0.0787
COVER_DATE_X_FRAC      = 0.3212
COVER_REFERENCE_X_FRAC = 0.5636


def draw_cover_page(c, target, scan_date_str, reference_code):
    width, height = A4

    # --- Fond : image gabarit fournie, etiree exactement sur la page A4 ---
    if os.path.exists(COVER_TEMPLATE_PATH):
        c.drawImage(
            COVER_TEMPLATE_PATH, 0, 0,
            width=width, height=height,
            preserveAspectRatio=False, mask="auto",
        )
    else:
        c.setFillColor(COLOR_WHITE)
        c.rect(0, 0, width, height, fill=1, stroke=0)

    # --- Valeurs dynamiques posees juste au-dessus des lignes CLIENT / DATE / REFERENCE ---
    # y mesure depuis le HAUT de l'image -> conversion en y ReportLab (origine en bas)
    value_y = height - (height * COVER_LINE_Y_FRAC) + 2.2 * mm

    c.setFillColor(COLOR_DARK)
    c.setFont("Helvetica", 10.5)

    client_x = width * COVER_CLIENT_X_FRAC
    date_x = width * COVER_DATE_X_FRAC
    reference_x = width * COVER_REFERENCE_X_FRAC

    # Tronquer la cible si trop longue pour ne pas deborder de la colonne CLIENT
    display_target = target if len(target) <= 30 else target[:27] + "..."

    c.drawString(client_x, value_y, display_target)
    c.drawString(date_x, value_y, scan_date_str)
    c.drawString(reference_x, value_y, reference_code)


# ---------------------------------------------------------------------------
# Generateur principal
# ---------------------------------------------------------------------------
def generate_report_pdf(scan, results):
    buffer = io.BytesIO()
    styles = get_styles()

    scan_date = scan.created_at.strftime("%d/%m/%Y à %H:%M") if scan.created_at else "N/A"
    scan_date_short = scan.created_at.strftime("%d/%m/%Y") if scan.created_at else "N/A"
    reference_code = generate_reference_code()

    # ------------------------------------------------------------------ #
    # ETAPE 1 : page de garde dessinee directement (canvas pur, page 1)
    # ------------------------------------------------------------------ #
    cover_buffer = io.BytesIO()
    cover_canvas = pdfcanvas.Canvas(cover_buffer, pagesize=A4)
    draw_cover_page(cover_canvas, scan.target_url, scan_date_short, reference_code)
    cover_canvas.showPage()
    cover_canvas.save()
    cover_buffer.seek(0)

    # ------------------------------------------------------------------ #
    # ETAPE 2 : reste du document construit avec Platypus (pages 2+)
    # ------------------------------------------------------------------ #
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=22*mm, bottomMargin=22*mm,
        leftMargin=20*mm, rightMargin=20*mm,
        title="Rapport de diagnostic CyberScan",
        author="CyberScan",
    )

    story = []
    page_width = A4[0] - 40*mm
    counts = count_severities(results)
    total_findings = sum(counts.values())

    selected = [MODULES_NAMES.get(m, m) for m in scan.scan_type.split(",")]

    # ------------------------------------------------------------------ #
    # PAGE 2 : Mentions legales / consentement du client
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Mentions légales & consentement", styles["SectionTitle"]))

    story.append(Paragraph(
        "Ce document constitue un rapport de diagnostic de sécurité réalisé à l'aide de la toolbox "
        "CyberScan. Il est établi dans un cadre strictement professionnel et éthique, conformément à "
        "la législation française et européenne en vigueur.",
        styles["LegalBody"],
    ))

    story.append(Paragraph("Cadre légal applicable", styles["LegalTitle"]))
    legal_points = [
        "<b>Art. 323-1 à 323-7 du Code pénal</b> — Accès et maintien frauduleux dans un système de "
        "traitement automatisé de données (STAD). Tout test réalisé sans autorisation constitue une "
        "infraction pénale.",
        "<b>RGPD (Règlement UE 2016/679)</b> — Encadre le traitement des données à caractère personnel "
        "pouvant être rencontrées au cours du diagnostic.",
        "<b>Directive NIS 2 (UE 2022/2555)</b> — Obligations de cybersécurité applicables aux entités "
        "essentielles et importantes.",
    ]
    for point in legal_points:
        story.append(Paragraph(f"• {point}", styles["LegalBullet"]))

    story.append(Paragraph("Consentement du client", styles["LegalTitle"]))
    story.append(Paragraph(
        f"Le client identifié par la cible <b>{scan.target_url}</b> reconnaît avoir donné son "
        f"autorisation écrite et explicite préalable à la réalisation de ce diagnostic de sécurité, "
        f"dans le périmètre, la fenêtre temporelle et les conditions convenues avec l'équipe CyberScan. "
        f"Le présent rapport, daté du {scan_date}, est remis exclusivement à ce client et ne saurait "
        f"être diffusé à un tiers sans son accord écrit.",
        styles["LegalBody"],
    ))

    story.append(Paragraph("Confidentialité et usage des résultats", styles["LegalTitle"]))
    story.append(Paragraph(
        "Les informations contenues dans ce rapport sont strictement confidentielles. Les résultats "
        "ne doivent être utilisés qu'à des fins de remédiation des vulnérabilités identifiées. Toute "
        "exploitation des failles décrites en dehors du périmètre autorisé est interdite et engage la "
        "responsabilité civile et pénale de son auteur.",
        styles["LegalBody"],
    ))

    story.append(Paragraph("Mesures de sécurité appliquées par l'outil", styles["LegalTitle"]))
    security_points = [
        "Authentification sécurisée et verrouillage de compte après tentatives échouées répétées.",
        "Chiffrement des résultats de scan en base de données (Fernet, AES-128).",
        "Journal d'audit horodaté de toutes les actions sensibles (connexion, scan, export).",
        "Cloisonnement des données par utilisateur et contrôle d'accès par rôle (RBAC).",
    ]
    for point in security_points:
        story.append(Paragraph(f"• {point}", styles["LegalBullet"]))

    story.append(PageBreak())

    # ------------------------------------------------------------------ #
    # PAGE 3 : Synthese du diagnostic
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Synthèse du diagnostic", styles["SectionTitle"]))

    story.append(Paragraph(f"<b>Date du diagnostic :</b> {scan_date}", styles["BodyText2"]))
    story.append(Paragraph(f"<b>Cible :</b> {scan.target_url}", styles["BodyText2"]))
    story.append(Paragraph(
        f"<b>Diagnostics sélectionnés :</b> {', '.join(selected)}",
        styles["BodyText2"],
    ))

    story.append(Spacer(1, 6*mm))

    critical_high = counts["critical"] + counts["high"]
    if critical_high == 0:
        risk_level = "faible"
        risk_text = "Aucune vulnérabilité critique ou élevée n'a été détectée lors de ce diagnostic."
    elif critical_high <= 2:
        risk_level = "modéré"
        risk_text = "Quelques vulnérabilités significatives nécessitent une attention rapide."
    else:
        risk_level = "élevé"
        risk_text = "Plusieurs vulnérabilités critiques ont été identifiées et nécessitent une remédiation immédiate."

    story.append(Paragraph(
        f"Le diagnostic de sécurité réalisé sur <b>{scan.target_url}</b> le {scan_date} "
        f"a permis d'identifier <b>{total_findings} constatation(s)</b>, dont "
        f"<font color='{COLOR_CRITICAL.hexval()}'><b>{counts['critical']} critique(s)</b></font> et "
        f"<font color='{COLOR_HIGH.hexval()}'><b>{counts['high']} élevée(s)</b></font>. "
        f"Le niveau de risque global est estimé comme <b>{risk_level}</b>. {risk_text}",
        styles["BodyText2"],
    ))

    story.append(Spacer(1, 6*mm))

    # Tableau de synthese des vulnerabilites
    summary_data = [
        ["CRITIQUE", "ÉLEVÉE", "MOYENNE", "FAIBLE", "INFO"],
        [str(counts["critical"]), str(counts["high"]), str(counts["medium"]),
         str(counts["low"]), str(counts["info"])],
    ]
    col_w = page_width / 5
    summary_table = Table(summary_data, colWidths=[col_w]*5)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), COLOR_CRITICAL),
        ("BACKGROUND", (1,0), (1,0), COLOR_HIGH),
        ("BACKGROUND", (2,0), (2,0), COLOR_MEDIUM),
        ("BACKGROUND", (3,0), (3,0), COLOR_LOW),
        ("BACKGROUND", (4,0), (4,0), COLOR_INFO),
        ("TEXTCOLOR",  (0,0), (-1,0), COLOR_WHITE),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,0), 9),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("FONTNAME",   (0,1), (-1,1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,1), (-1,1), 18),
        ("TEXTCOLOR",  (0,1), (0,1), COLOR_CRITICAL),
        ("TEXTCOLOR",  (1,1), (1,1), COLOR_HIGH),
        ("TEXTCOLOR",  (2,1), (2,1), COLOR_MEDIUM),
        ("TEXTCOLOR",  (3,1), (3,1), COLOR_LOW),
        ("TEXTCOLOR",  (4,1), (4,1), COLOR_INFO),
        ("BACKGROUND", (0,1), (-1,1), COLOR_LIGHT_BG),
        ("BOX",        (0,0), (-1,-1), 0.5, COLOR_GRAY),
        ("INNERGRID",  (0,0), (-1,-1), 0.5, COLOR_GRAY),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8*mm))

    # ------------------------------------------------------------------ #
    # METHODOLOGIE (sur la meme page 3 que la synthese)
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Méthodologie", styles["SectionTitle"]))
    story.append(Paragraph(
        "Le diagnostic a été réalisé à l'aide de la toolbox CyberScan, qui intègre des outils "
        "de référence en cybersécurité. Les tests ont été conduits de manière automatisée et "
        "non intrusive, dans le respect du périmètre défini avec le client.",
        styles["BodyText2"],
    ))

    tools_data = [["Module", "Outils utilisés", "Objectif"]]
    tools_map = {
        "network": ["Nmap",             "Reconnaissance réseau, scan de ports et services"],
        "web":     ["SQLmap, HTTP",     "Injection SQL, en-têtes de sécurité, endpoints API, certificat SSL"],
        "infra":   ["Hydra",            "Brute force SSH/FTP, accès anonyme"],
        "pentest": ["John the Ripper",  "Craquage de hash, politique de mots de passe"],
    }
    for mod_key in results.get("modules", {}):
        if mod_key in tools_map:
            mod_name = MODULES_NAMES.get(mod_key, mod_key)
            tools_data.append([mod_name, tools_map[mod_key][0], tools_map[mod_key][1]])

    if len(tools_data) > 1:
        tools_table = Table(
            tools_data,
            colWidths=[page_width*0.25, page_width*0.25, page_width*0.50],
        )
        tools_table.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), COLOR_PRIMARY),
            ("TEXTCOLOR",   (0,0), (-1,0), COLOR_WHITE),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,0), 9),
            ("FONTNAME",    (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",    (0,1), (-1,-1), 9),
            ("ALIGN",       (0,0), (-1,0), "CENTER"),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("BOX",         (0,0), (-1,-1), 0.5, COLOR_GRAY),
            ("INNERGRID",   (0,0), (-1,-1), 0.5, COLOR_GRAY),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [COLOR_WHITE, COLOR_LIGHT_BG]),
        ]))
        story.append(tools_table)

    story.append(PageBreak())

    # ------------------------------------------------------------------ #
    # RESULTATS DETAILLES
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Résultats détaillés par module", styles["SectionTitle"]))

    module_index = 1
    for mod_key, mod_data in results.get("modules", {}).items():
        mod_name = mod_data.get("name", mod_key)
        findings = mod_data.get("findings", [])

        story.append(Paragraph(f"{module_index}. {mod_name}", styles["SubsectionTitle"]))
        story.append(Paragraph(
            f"{len(findings)} constatation(s) identifiée(s) dans ce module.",
            styles["BodyText2"],
        ))

        if findings:
            finding_data = [["Sévérité", "Constatation", "Détail / Recommandation"]]
            for finding in findings:
                sev       = finding.get("severity", "info")
                sev_label = SEVERITY_LABELS.get(sev, sev.upper())
                sev_color = SEVERITY_COLORS.get(sev, COLOR_INFO)

                sev_para = Paragraph(
                    f'<font color="{sev_color.hexval()}"><b>{sev_label}</b></font>',
                    ParagraphStyle("sev", fontName="Helvetica-Bold", fontSize=8, alignment=TA_CENTER),
                )
                title_para = Paragraph(
                    finding.get("title", ""),
                    ParagraphStyle("ftitle", fontName="Helvetica-Bold", fontSize=9),
                )
                detail_para = Paragraph(
                    finding.get("detail", ""),
                    ParagraphStyle("fdetail", fontName="Helvetica", fontSize=8,
                                   textColor=COLOR_GRAY, leading=11),
                )
                finding_data.append([sev_para, title_para, detail_para])

            finding_table = Table(
                finding_data,
                colWidths=[page_width*0.12, page_width*0.33, page_width*0.55],
            )
            finding_table.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (-1,0), COLOR_PRIMARY),
                ("TEXTCOLOR",   (0,0), (-1,0), COLOR_WHITE),
                ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (-1,0), 9),
                ("ALIGN",       (0,0), (0,-1), "CENTER"),
                ("VALIGN",      (0,0), (-1,-1), "TOP"),
                ("BOX",         (0,0), (-1,-1), 0.5, COLOR_GRAY),
                ("INNERGRID",   (0,0), (-1,-1), 0.5, HexColor("#E5E7EB")),
                ("TOPPADDING",    (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING",   (0,0), (-1,-1), 6),
                ("RIGHTPADDING",  (0,0), (-1,-1), 6),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [COLOR_WHITE, COLOR_LIGHT_BG]),
            ]))
            story.append(finding_table)

        story.append(Spacer(1, 5*mm))
        module_index += 1

    story.append(PageBreak())

    # ------------------------------------------------------------------ #
    # RECOMMANDATIONS
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Recommandations générales", styles["SectionTitle"]))

    recommendations = []
    if counts["critical"] > 0:
        recommendations.append(
            "<b>Priorité immédiate :</b> Corriger les vulnérabilités critiques identifiées dans les 48 heures."
        )
    if counts["high"] > 0:
        recommendations.append(
            "<b>Court terme (1–2 semaines) :</b> Traiter les vulnérabilités de sévérité élevée."
        )
    recommendations.extend([
        "<b>Politique de mots de passe :</b> Imposer une complexité minimale (12 caractères, "
        "majuscule, minuscule, chiffre, caractère spécial). Utiliser bcrypt ou Argon2.",
        "<b>En-têtes de sécurité HTTP :</b> Configurer CSP, HSTS, X-Frame-Options et "
        "X-Content-Type-Options sur tous les serveurs web.",
        "<b>Gestion des accès :</b> Désactiver les services inutiles (FTP, Telnet). "
        "Restreindre l'accès SSH par clé uniquement.",
        "<b>Surveillance continue :</b> Mettre en place un SIEM et planifier des audits trimestriels.",
        "<b>Formation :</b> Sensibiliser l'ensemble des collaborateurs aux bonnes pratiques de cybersécurité.",
    ])

    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f"{i}. {rec}", styles["BodyText2"]))

    # ------------------------------------------------------------------ #
    # CONCLUSION
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Conclusion", styles["SectionTitle"]))
    story.append(Paragraph(
        f"Ce diagnostic a permis d'identifier {total_findings} constatation(s) sur la cible "
        f"{scan.target_url}. Le niveau de risque global est évalué comme <b>{risk_level}</b>.",
        styles["BodyText2"],
    ))
    story.append(Paragraph(
        "L'équipe CyberScan recommande de prioriser la remédiation des vulnérabilités "
        "critiques et élevées, puis de mettre en place une stratégie de sécurité continue.",
        styles["BodyText2"],
    ))

    story.append(Spacer(1, 12*mm))
    story.append(HRFlowable(width="40%", thickness=1, color=COLOR_EMERALD, spaceAfter=3*mm))
    story.append(Paragraph("L'équipe CyberScan", styles["CoverInfo"]))
    story.append(Paragraph(
        "Détecter aujourd'hui. Protéger demain.",
        ParagraphStyle("slogan", fontName="Helvetica-Oblique", fontSize=9,
                        textColor=COLOR_EMERALD, alignment=TA_CENTER),
    ))

    # ------------------------------------------------------------------ #
    # EN-TETE / PIED DE PAGE (pages 2+)
    # ------------------------------------------------------------------ #
    def add_header_footer(canvas_obj, doc_obj):
        canvas_obj.saveState()
        canvas_obj.setFont("Helvetica-Bold", 8)
        canvas_obj.setFillColor(COLOR_PRIMARY)
        canvas_obj.drawString(20*mm, A4[1] - 12*mm, "CYBERSCAN")
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(COLOR_GRAY)
        canvas_obj.drawRightString(A4[0] - 20*mm, A4[1] - 12*mm, "Rapport de diagnostic — Confidentiel")
        canvas_obj.setStrokeColor(COLOR_EMERALD)
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(20*mm, A4[1] - 14*mm, A4[0] - 20*mm, A4[1] - 14*mm)

        canvas_obj.setFont("Helvetica", 7)
        canvas_obj.setFillColor(COLOR_GRAY)
        canvas_obj.drawString(
            20*mm, 12*mm,
            f"CyberScan \u00a9 2026 — Réf. {reference_code} — Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}",
        )
        # +1 car la page de garde (canvas pur) n'est pas comptee par Platypus
        canvas_obj.drawRightString(A4[0] - 20*mm, 12*mm, f"Page {doc_obj.page + 1}")
        canvas_obj.line(20*mm, 15*mm, A4[0] - 20*mm, 15*mm)
        canvas_obj.restoreState()

    doc.build(story, onFirstPage=add_header_footer, onLaterPages=add_header_footer)
    buffer.seek(0)

    # ------------------------------------------------------------------ #
    # ETAPE 3 : fusion page de garde + reste du document
    # ------------------------------------------------------------------ #
    from pypdf import PdfReader, PdfWriter

    cover_reader = PdfReader(cover_buffer)
    body_reader = PdfReader(buffer)

    writer = PdfWriter()
    writer.add_page(cover_reader.pages[0])
    for page in body_reader.pages:
        writer.add_page(page)

    final_buffer = io.BytesIO()
    writer.write(final_buffer)
    final_buffer.seek(0)
    return final_buffer.getvalue()
