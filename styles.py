"""
PINK WEB SCANNER - STYLES & THEMING MODULE
Provides futuristic cyber security pink aesthetics with both Dark and Light themes.
"""

def get_custom_css(theme: str = "dark") -> str:
    """
    Returns custom CSS tailored for the selected theme: 'dark' or 'light'.
    Features glassmorphism, neon glows, cyber borders, and responsive design.
    """
    if theme == "dark":
        bg_primary = "#160D19"
        bg_panel = "rgba(38, 23, 43, 0.82)"
        bg_card = "rgba(45, 25, 52, 0.75)"
        text_primary = "#FFFFFF"
        text_secondary = "#FFD6E8"
        text_muted = "#C7A6BA"
        border_glow = "rgba(255, 79, 163, 0.35)"
        border_active = "rgba(255, 105, 180, 0.7)"
        sidebar_bg = "#110914"
        stat_badge_bg = "rgba(84, 38, 94, 0.6)"
        code_bg = "#1e1022"
        box_shadow = "0 8px 32px 0 rgba(255, 79, 163, 0.15)"
    else: # light theme
        bg_primary = "#FFF0F6"
        bg_panel = "rgba(255, 255, 255, 0.9)"
        bg_card = "rgba(255, 245, 249, 0.85)"
        text_primary = "#2B1130"
        text_secondary = "#54265E"
        text_muted = "#7A4D6F"
        border_glow = "rgba(255, 79, 163, 0.4)"
        border_active = "rgba(255, 79, 163, 0.8)"
        sidebar_bg = "#FFE4EF"
        stat_badge_bg = "rgba(255, 214, 232, 0.8)"
        code_bg = "#fae8f0"
        box_shadow = "0 8px 32px 0 rgba(255, 79, 163, 0.12)"

    css = f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

    :root {{
        --hot-pink: #FF4FA3;
        --neon-pink: #FF69B4;
        --soft-pink: #FFD6E8;
        --light-pink: #FFF0F6;
        --deep-purple: #54265E;
        --dark-bg: {bg_primary};
        --dark-panel: {bg_panel};
        --card-bg: {bg_card};
        --text-primary: {text_primary};
        --text-secondary: {text_secondary};
        --text-muted: {text_muted};
        --border-glow: {border_glow};
        --border-active: {border_active};
        --box-shadow: {box_shadow};
    }}

    /* Global Streamlit Overrides */
    .stApp {{
        background-color: var(--dark-bg);
        color: var(--text-primary);
        font-family: 'Inter', sans-serif;
    }}

    header[data-testid="stHeader"] {{
        background: transparent;
    }}

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {{
        background-color: {sidebar_bg} !important;
        border-right: 1px solid var(--border-glow);
    }}

    section[data-testid="stSidebar"] .stMarkdown {{
        color: var(--text-primary);
    }}

    /* Futuristic Header Banner */
    .cyber-banner {{
        background: linear-gradient(135deg, rgba(84, 38, 94, 0.85) 0%, rgba(255, 79, 163, 0.3) 100%);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid var(--border-glow);
        border-radius: 16px;
        padding: 24px 28px;
        margin-bottom: 24px;
        box-shadow: var(--box-shadow);
        position: relative;
        overflow: hidden;
    }}

    .cyber-banner::after {{
        content: '';
        position: absolute;
        top: 0;
        right: 0;
        width: 150px;
        height: 100%;
        background: radial-gradient(circle, rgba(255, 105, 180, 0.2) 0%, transparent 70%);
        pointer-events: none;
    }}

    .cyber-title {{
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #FFFFFF, #FF69B4, #FF4FA3);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: -0.5px;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }}

    .cyber-subtitle {{
        color: var(--text-secondary);
        font-size: 0.95rem;
        font-weight: 500;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        margin-top: 6px;
    }}

    /* Cards & Glassmorphism */
    .cyber-card {{
        background: var(--dark-panel);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid var(--border-glow);
        border-radius: 14px;
        padding: 20px;
        margin-bottom: 18px;
        box-shadow: var(--box-shadow);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }}

    .cyber-card:hover {{
        border-color: var(--border-active);
        box-shadow: 0 12px 40px rgba(255, 79, 163, 0.25);
        transform: translateY(-2px);
    }}

    .stat-card {{
        background: var(--card-bg);
        border: 1px solid var(--border-glow);
        border-radius: 14px;
        padding: 18px;
        text-align: left;
        position: relative;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }}

    .stat-card:hover {{
        border-color: var(--hot-pink);
        transform: translateY(-2px);
    }}

    .stat-value {{
        font-size: 1.85rem;
        font-weight: 700;
        color: var(--hot-pink);
        margin: 4px 0;
        font-family: 'JetBrains Mono', monospace;
    }}

    .stat-label {{
        font-size: 0.82rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
    }}

    .stat-badge {{
        display: inline-block;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
        background: {stat_badge_bg};
        color: #FF69B4;
        border: 1px solid rgba(255, 105, 180, 0.4);
    }}

    /* Badges & Tags */
    .badge-pass {{
        background: rgba(34, 197, 94, 0.15);
        color: #4ade80;
        border: 1px solid rgba(74, 222, 128, 0.4);
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.8rem;
    }}

    .badge-warn {{
        background: rgba(234, 179, 8, 0.15);
        color: #facc15;
        border: 1px solid rgba(250, 204, 21, 0.4);
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.8rem;
    }}

    .badge-fail {{
        background: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid rgba(248, 113, 113, 0.4);
        padding: 3px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.8rem;
    }}

    .badge-tech {{
        background: rgba(255, 79, 163, 0.15);
        color: #FF69B4;
        border: 1px solid rgba(255, 79, 163, 0.35);
        padding: 4px 12px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
        margin: 3px;
    }}

    /* Custom Buttons */
    .stButton>button {{
        background: linear-gradient(135deg, #FF4FA3 0%, #54265E 100%) !important;
        color: #FFFFFF !important;
        border: 1px solid rgba(255, 105, 180, 0.5) !important;
        border-radius: 10px !important;
        font-weight: 600 !important;
        padding: 8px 20px !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(255, 79, 163, 0.25) !important;
    }}

    .stButton>button:hover {{
        background: linear-gradient(135deg, #FF69B4 0%, #FF4FA3 100%) !important;
        box-shadow: 0 6px 22px rgba(255, 79, 163, 0.5) !important;
        transform: translateY(-1px) !important;
    }}

    /* Input Fields */
    .stTextInput>div>div>input {{
        background: {code_bg} !important;
        border: 1px solid var(--border-glow) !important;
        color: var(--text-primary) !important;
        border-radius: 10px !important;
        padding: 10px 14px !important;
        font-size: 0.95rem !important;
    }}

    .stTextInput>div>div>input:focus {{
        border-color: var(--hot-pink) !important;
        box-shadow: 0 0 12px rgba(255, 79, 163, 0.4) !important;
    }}

    /* Breadcrumbs */
    .breadcrumb {{
        color: var(--text-muted);
        font-size: 0.85rem;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 6px;
    }}

    .breadcrumb span.active {{
        color: var(--hot-pink);
        font-weight: 600;
    }}

    /* Terminal / Code Box */
    .cyber-terminal {{
        background: {code_bg};
        border: 1px solid var(--border-glow);
        border-radius: 10px;
        padding: 14px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        color: #FFD6E8;
        overflow-x: auto;
    }}

    /* Table styling */
    .dataframe {{
        background-color: var(--dark-panel) !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border-glow) !important;
        border-radius: 8px !important;
    }}

    /* Clean divider */
    hr {{
        border-color: var(--border-glow) !important;
        margin: 20px 0 !important;
    }}
    </style>
    """
    return css
