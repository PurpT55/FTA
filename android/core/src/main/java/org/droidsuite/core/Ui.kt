package org.droidsuite.core

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Tiny programmatic view helpers so the apps need no XML resources or AndroidX. */
object Ui {
    const val BG = 0xFF101418.toInt()
    const val CARD = 0xFF1B2129.toInt()
    const val TEXT = 0xFFE6EAF0.toInt()
    const val MUTED = 0xFF9AA4B2.toInt()
    const val ACCENT = 0xFF4EA1FF.toInt()

    fun sevColor(s: Severity): Int = when (s) {
        Severity.CRITICAL -> 0xFFE5484D.toInt()
        Severity.HIGH -> 0xFFF76B15.toInt()
        Severity.MEDIUM -> 0xFFFFB224.toInt()
        Severity.LOW -> 0xFF4EA1FF.toInt()
        Severity.INFO -> 0xFF9AA4B2.toInt()
    }

    fun scoreColor(v: Int): Int = when {
        v >= 60 -> sevColor(Severity.CRITICAL)
        v >= 35 -> sevColor(Severity.HIGH)
        v >= 15 -> sevColor(Severity.MEDIUM)
        else -> 0xFF30A46C.toInt()
    }

    fun dp(ctx: Context, v: Int) = (v * ctx.resources.displayMetrics.density).toInt()

    fun vbox(ctx: Context, pad: Int = 0): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(ctx, pad), dp(ctx, pad), dp(ctx, pad), dp(ctx, pad))
    }

    fun hbox(ctx: Context): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
    }

    fun text(ctx: Context, s: CharSequence, size: Float = 14f, color: Int = TEXT, bold: Boolean = false): TextView =
        TextView(ctx).apply {
            text = s
            textSize = size
            setTextColor(color)
            if (bold) typeface = Typeface.DEFAULT_BOLD
            setTextIsSelectable(false)
        }

    fun card(ctx: Context, accent: Int? = null): LinearLayout = vbox(ctx, 12).apply {
        background = GradientDrawable().apply {
            cornerRadius = dp(ctx, 10).toFloat()
            setColor(CARD)
            if (accent != null) setStroke(dp(ctx, 2), accent)
        }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            .apply { setMargins(0, dp(ctx, 6), 0, dp(ctx, 6)) }
    }

    fun button(ctx: Context, label: String, onClick: () -> Unit): Button = Button(ctx).apply {
        text = label
        isAllCaps = false
        setOnClickListener { onClick() }
    }

    fun weighted(v: View, weight: Float = 1f): View {
        v.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, weight).apply { setMargins(4, 4, 4, 4) }
        return v
    }

    fun chip(ctx: Context, s: String, color: Int): TextView = text(ctx, " $s ", 11f, Color.BLACK, true).apply {
        background = GradientDrawable().apply { cornerRadius = dp(ctx, 6).toFloat(); setColor(color) }
    }
}
