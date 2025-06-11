import colorsys


def generate_palette(n):
    palette = []
    for i in range(n):
        h = i / n
        r, g, b = colorsys.hsv_to_rgb(h, 0.6, 0.9),
        palette.append(f"#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}")

    return palette
