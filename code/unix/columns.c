/*
 * columns.c - implementation of the `Columns' GTK layout container.
 */

#include <assert.h>
#include <gtk/gtk.h>
#include "defs.h"
#include "gtkcompat.h"
#include "columns.h"

#if GTK_CHECK_VERSION(2,0,0)
/* The "focus" method lives in GtkWidget from GTK 2 onwards, but it
 * was in GtkContainer in GTK 1 */
#define FOCUS_METHOD_SUPERCLASS GtkWidget
#define FOCUS_METHOD_LOCATION widget_class /* used in columns_init */
#define CHILD_FOCUS(cont, dir) gtk_widget_child_focus(GTK_WIDGET(cont), dir)
#else
#define FOCUS_METHOD_SUPERCLASS GtkContainer
#define FOCUS_METHOD_LOCATION container_class
#define CHILD_FOCUS(cont, dir) gtk_container_focus(GTK_CONTAINER(cont), dir)
#endif

static void columns_init(Columns *cols);
static void columns_class_init(ColumnsClass *klass);
#if !GTK_CHECK_VERSION(2,0,0)
static void columns_finalize(GtkObject *object);
#else
static void columns_finalize(GObject *object);
#endif
static void columns_map(GtkWidget *widget);
static void columns_unmap(GtkWidget *widget);
#if !GTK_CHECK_VERSION(2,0,0)
static void columns_draw(GtkWidget *widget, GdkRectangle *area);
static gint columns_expose(GtkWidget *widget, GdkEventExpose *event);
#endif
static void columns_base_add(GtkContainer *container, GtkWidget *widget);
static void columns_remove(GtkContainer *container, GtkWidget *widget);
static void columns_forall(GtkContainer *container, gboolean include_internals,
                           GtkCallback callback, gpointer callback_data);
static gint columns_focus(FOCUS_METHOD_SUPERCLASS *container,
                          GtkDirectionType dir);
static GType columns_child_type(GtkContainer *container);
#if GTK_CHECK_VERSION(3,0,0)
static void columns_get_preferred_width(GtkWidget *widget,
                                        gint *min, gint *nat);
static void columns_get_preferred_height(GtkWidget *widget,
                                         gint *min, gint *nat);
static void columns_get_preferred_width_for_height(GtkWidget *widget,
                                                   gint height,
                                                   gint *min, gint *nat);
static void columns_get_preferred_height_for_width(GtkWidget *widget,
                                                   gint width,
                                                   gint *min, gint *nat);
#else
static void columns_size_request(GtkWidget *widget, GtkRequisition *req);
#endif
static void columns_size_allocate(GtkWidget *widget, GtkAllocation *alloc);

static GtkContainerClass *parent_class = NULL;

#if !GTK_CHECK_VERSION(2,0,0)
GType columns_get_type(void)
{
    static GType columns_type = 0;

    if (!columns_type) {
        static const GtkTypeInfo columns_info = {
            "Columns",
            sizeof(Columns),
            sizeof(ColumnsClass),
            (GtkClassInitFunc) columns_class_init,
            (GtkObjectInitFunc) columns_init,
            /* reserved_1 */ NULL,
            /* reserved_2 */ NULL,
            (GtkClassInitFunc) NULL,
        };

        columns_type = gtk_type_unique(GTK_TYPE_CONTAINER, &columns_info);
    }

    return columns_type;
}
#else
GType columns_get_type(void)
{
    static GType columns_type = 0;

    if (!columns_type) {
        static const GTypeInfo columns_info = {
            sizeof(ColumnsClass),
            NULL,
            NULL,
            (GClassInitFunc) columns_class_init,
            NULL,
            NULL,
            sizeof(Columns),
            0,
            (GInstanceInitFunc)columns_init,
        };

        columns_type = g_type_register_static(GTK_TYPE_CONTAINER, "Columns",
                                              &columns_info, 0);
    }

    return columns_type;
}
#endif

static gint (*columns_inherited_focus)(FOCUS_METHOD_SUPERCLASS *container,
                                       GtkDirectionType direction);

static void columns_class_init(ColumnsClass *klass)
{
#if !GTK_CHECK_VERSION(2,0,0)
    GtkObjectClass *object_class = (GtkObjectClass *)klass;
    GtkWidgetClass *widget_class = (GtkWidgetClass *)klass;
    GtkContainerClass *container_class = (GtkContainerClass *)klass;
#else
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    GtkWidgetClass *widget_class = GTK_WIDGET_CLASS(klass);
    GtkContainerClass *container_class = GTK_CONTAINER_CLASS(klass);
#endif

#if !GTK_CHECK_VERSION(2,0,0)
    parent_class = gtk_type_class(GTK_TYPE_CONTAINER);
#else
    parent_class = g_type_class_peek_parent(klass);
#endif

    object_class->finalize = columns_finalize;
    widget_class->map = columns_map;
    widget_class->unmap = columns_unmap;
#if !GTK_CHECK_VERSION(2,0,0)
    widget_class->draw = columns_draw;
    widget_class->expose_event = columns_expose;
#endif
#if GTK_CHECK_VERSION(3,0,0)
    widget_class->get_preferred_width = columns_get_preferred_width;
    widget_class->get_preferred_height = columns_get_preferred_height;
    widget_class->get_preferred_width_for_height =
        columns_get_preferred_width_for_height;
    widget_class->get_preferred_height_for_width =
        columns_get_preferred_height_for_width;
#else
    widget_class->size_request = columns_size_request;
#endif
    widget_class->size_allocate = columns_size_allocate;

    container_class->add = columns_base_add;
    container_class->remove = columns_remove;
    container_class->forall = columns_forall;
    container_class->child_type = columns_child_type;

    /* Save the previous value of this method. */
    if (!columns_inherited_focus)
        columns_inherited_focus = FOCUS_METHOD_LOCATION->focus;
    FOCUS_METHOD_LOCATION->focus = columns_focus;
}

static void columns_init(Columns *cols)
{
    gtk_widget_set_has_window(GTK_WIDGET(cols), false);

    cols->children = NULL;
    cols->spacing = 0;
}

static void columns_child_free(gpointer vchild)
{
    ColumnsChild *child = (ColumnsChild *)vchild;
    if (child->percentages)
        g_free(child->percentages);
    g_free(child);
}

static void columns_finalize(
#if !GTK_CHECK_VERSION(2,0,0)
    GtkObject *object
#else
    GObject *object
#endif
    )
{
    Columns *cols;

    g_return_if_fail(object != NULL);
    g_return_if_fail(IS_COLUMNS(object));

    cols = COLUMNS(object);

#if !GTK_CHECK_VERSION(2,0,0)
    {
        GList *node;
        for (node = cols->children; node; node = node->next)
            if (node->data)
                columns_child_free(node->data);
    }
    g_list_free(cols->children);
#else
    g_list_free_full(cols->children, columns_child_free);
#endif

    cols->children = NULL;

#if !GTK_CHECK_VERSION(2,0,0)
    GTK_OBJECT_CLASS(parent_class)->finalize(object);
#else
    G_OBJECT_CLASS(parent_class)->finalize(object);
#endif
}

/*
 * These appear to be thoroughly tedious functions; the only reason
 * we have to reimplement them at all is because we defined our own
 * format for our GList of children...
 */
static void columns_map(GtkWidget *widget)
{
    Columns *cols;
    ColumnsChild *child;
    GList *children;

    g_return_if_fail(widget != NULL);
    g_return_if_fail(IS_COLUMNS(widget));

    cols = COLUMNS(widget);
    gtk_widget_set_mapped(GTK_WIDGET(cols), true);

    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {
        if (child->widget &&
            gtk_widget_get_visible(child->widget) &&
            !gtk_widget_get_mapped(child->widget))
            gtk_widget_map(child->widget);
    }
}
static void columns_unmap(GtkWidget *widget)
{
    Columns *cols;
    ColumnsChild *child;
    GList *children;

    g_return_if_fail(widget != NULL);
    g_return_if_fail(IS_COLUMNS(widget));

    cols = COLUMNS(widget);
    gtk_widget_set_mapped(GTK_WIDGET(cols), false);

    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {
        if (child->widget &&
            gtk_widget_get_visible(child->widget) &&
            gtk_widget_get_mapped(child->widget))
            gtk_widget_unmap(child->widget);
    }
}
#if !GTK_CHECK_VERSION(2,0,0)
static void columns_draw(GtkWidget *widget, GdkRectangle *area)
{
    Columns *cols;
    ColumnsChild *child;
    GList *children;
    GdkRectangle child_area;

    g_return_if_fail(widget != NULL);
    g_return_if_fail(IS_COLUMNS(widget));

    if (GTK_WIDGET_DRAWABLE(widget)) {
        cols = COLUMNS(widget);

        for (children = cols->children;
             children && (child = children->data);
             children = children->next) {
            if (child->widget &&
                GTK_WIDGET_DRAWABLE(child->widget) &&
                gtk_widget_intersect(child->widget, area, &child_area))
                gtk_widget_draw(child->widget, &child_area);
        }
    }
}
static gint columns_expose(GtkWidget *widget, GdkEventExpose *event)
{
    Columns *cols;
    ColumnsChild *child;
    GList *children;
    GdkEventExpose child_event;

    g_return_val_if_fail(widget != NULL, false);
    g_return_val_if_fail(IS_COLUMNS(widget), false);
    g_return_val_if_fail(event != NULL, false);

    if (GTK_WIDGET_DRAWABLE(widget)) {
        cols = COLUMNS(widget);
        child_event = *event;

        for (children = cols->children;
             children && (child = children->data);
             children = children->next) {
            if (child->widget &&
                GTK_WIDGET_DRAWABLE(child->widget) &&
                GTK_WIDGET_NO_WINDOW(child->widget) &&
                gtk_widget_intersect(child->widget, &event->area,
                                     &child_event.area))
                gtk_widget_event(child->widget, (GdkEvent *)&child_event);
        }
    }
    return false;
}
#endif

static void columns_base_add(GtkContainer *container, GtkWidget *widget)
{
    Columns *cols;

    g_return_if_fail(container != NULL);
    g_return_if_fail(IS_COLUMNS(container));
    g_return_if_fail(widget != NULL);

    cols = COLUMNS(container);

    /*
     * Default is to add a new widget spanning all columns.
     */
    columns_add(cols, widget, 0, 0);   /* 0 means ncols */
}

static void columns_remove(GtkContainer *container, GtkWidget *widget)
{
    Columns *cols;
    ColumnsChild *child;
    GtkWidget *childw;
    GList *children;

    g_return_if_fail(container != NULL);
    g_return_if_fail(IS_COLUMNS(container));
    g_return_if_fail(widget != NULL);

    cols = COLUMNS(container);

    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {
        if (child->widget != widget)
            continue;

        bool need_layout = false;
        if (gtk_widget_get_visible(widget))
            need_layout = true;
        gtk_widget_unparent(widget);
        cols->children = g_list_remove_link(cols->children, children);
        g_list_free(children);

        /* Unlink this widget from its valign list, and if anything
         * else on the list is still visible, ensure we recompute our
         * layout */
        for (ColumnsChild *ch = child->valign_next; ch != child;
             ch = ch->valign_next)
            if (gtk_widget_get_visible(ch->widget))
                need_layout = true;
        child->valign_next->valign_prev = child->valign_prev;
        child->valign_prev->valign_next = child->valign_next;

        if (cols->vexpand == child)
            cols->vexpand = NULL;

        g_free(child);
        if (need_layout)
            gtk_widget_queue_resize(GTK_WIDGET(container));
        break;
    }

    for (children = cols->taborder;
         children && (childw = children->data);
         children = children->next) {
        if (childw != widget)
            continue;

        cols->taborder = g_list_remove_link(cols->taborder, children);
        g_list_free(children);
        break;
    }
}

static void columns_forall(GtkContainer *container, gboolean include_internals,
                           GtkCallback callback, gpointer callback_data)
{
    Columns *cols;
    ColumnsChild *child;
    GList *children, *next;

    g_return_if_fail(container != NULL);
    g_return_if_fail(IS_COLUMNS(container));
    g_return_if_fail(callback != NULL);

    cols = COLUMNS(container);

    for (children = cols->children;
         children && (child = children->data);
         children = next) {
        /*
         * We can't wait until after the callback to assign
         * `children = children->next', because the callback might
         * be gtk_widget_destroy, which would remove the link
         * `children' from the list! So instead we must get our
         * hands on the value of the `next' pointer _before_ the
         * callback.
         */
        next = children->next;
        if (child->widget)
            callback(child->widget, callback_data);
    }
}

static GType columns_child_type(GtkContainer *container)
{
    return GTK_TYPE_WIDGET;
}

GtkWidget *columns_new(gint spacing)
{
    Columns *cols;

#if !GTK_CHECK_VERSION(2,0,0)
    cols = gtk_type_new(columns_get_type());
#else
    cols = g_object_new(TYPE_COLUMNS, NULL);
#endif

    cols->spacing = spacing;

    return GTK_WIDGET(cols);
}

void columns_set_cols(Columns *cols, gint ncols, const gint *percentages)
{
    ColumnsChild *childdata;
    gint i;

    g_return_if_fail(cols != NULL);
    g_return_if_fail(IS_COLUMNS(cols));
    g_return_if_fail(ncols > 0);
    g_return_if_fail(percentages != NULL);

    childdata = g_new(ColumnsChild, 1);
    childdata->widget = NULL;
    childdata->ncols = ncols;
    childdata->percentages = g_new(gint, ncols);
    childdata->force_left = false;
    for (i = 0; i < ncols; i++)
        childdata->percentages[i] = percentages[i];

    cols->children = g_list_append(cols->children, childdata);
}

void columns_add(Columns *cols, GtkWidget *child,
                 gint colstart, gint colspan)
{
    ColumnsChild *childdata;

    g_return_if_fail(cols != NULL);
    g_return_if_fail(IS_COLUMNS(cols));
    g_return_if_fail(child != NULL);
    g_return_if_fail(gtk_widget_get_parent(child) == NULL);

    childdata = g_new(ColumnsChild, 1);
    childdata->widget = child;
    childdata->colstart = colstart;
    childdata->colspan = colspan;
    childdata->force_left = false;
    childdata->valign_next = childdata;
    childdata->valign_prev = childdata;
    childdata->percentages = NULL;

    cols->children = g_list_append(cols->children, childdata);
    cols->taborder = g_list_append(cols->taborder, child);

    gtk_widget_set_parent(child, GTK_WIDGET(cols));

    if (gtk_widget_get_realized(GTK_WIDGET(cols)))
        gtk_widget_realize(child);

    if (gtk_widget_get_visible(GTK_WIDGET(cols)) &&
        gtk_widget_get_visible(child)) {
        if (gtk_widget_get_mapped(GTK_WIDGET(cols)))
            gtk_widget_map(child);
        gtk_widget_queue_resize(child);
    }
}

static ColumnsChild *columns_find_child(Columns *cols, GtkWidget *widget)
{
    GList *children;
    ColumnsChild *child;

    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {

        if (child->widget == widget)
            return child;
    }

    return NULL;
}

void columns_force_left_align(Columns *cols, GtkWidget *widget)
{
    ColumnsChild *child;

    g_return_if_fail(cols != NULL);
    g_return_if_fail(IS_COLUMNS(cols));
    g_return_if_fail(widget != NULL);

    child = columns_find_child(cols, widget);
    g_return_if_fail(child != NULL);

    child->force_left = true;
    if (gtk_widget_get_visible(widget))
        gtk_widget_queue_resize(GTK_WIDGET(cols));
}

void columns_align_next_to(Columns *cols, GtkWidget *cw1, GtkWidget *cw2)
{
    ColumnsChild *child1, *child2;

    g_return_if_fail(cols != NULL);
    g_return_if_fail(IS_COLUMNS(cols));
    g_return_if_fail(cw1 != NULL);
    g_return_if_fail(cw2 != NULL);

    child1 = columns_find_child(cols, cw1);
    g_return_if_fail(child1 != NULL);
    child2 = columns_find_child(cols, cw2);
    g_return_if_fail(child2 != NULL);

    ColumnsChild *child1prev = child1->valign_prev;
    ColumnsChild *child2prev = child2->valign_prev;
    child1prev->valign_next = child2;
    child2->valign_prev = child1prev;
    child2prev->valign_next = child1;
    child1->valign_prev = child2prev;

    if (gtk_widget_get_visible(cw1) || gtk_widget_get_visible(cw2))
        gtk_widget_queue_resize(GTK_WIDGET(cols));
}

void columns_taborder_last(Columns *cols, GtkWidget *widget)
{
    GtkWidget *childw;
    GList *children;

    g_return_if_fail(cols != NULL);
    g_return_if_fail(IS_COLUMNS(cols));
    g_return_if_fail(widget != NULL);

    for (children = cols->taborder;
         children && (childw = children->data);
         children = children->next) {
        if (childw != widget)
            continue;

        cols->taborder = g_list_remove_link(cols->taborder, children);
        g_list_free(children);
        cols->taborder = g_list_append(cols->taborder, widget);
        break;
    }
}

void columns_vexpand(Columns *cols, GtkWidget *widget)
{
    g_return_if_fail(cols != NULL);
    g_return_if_fail(IS_COLUMNS(cols));
    g_return_if_fail(widget != NULL);

    ColumnsChild *child = columns_find_child(cols, widget);
    g_return_if_fail(child != NULL);

    cols->vexpand = child;
}

/*
 * Override GtkContainer's focus movement so the user can
 * explicitly specify the tab order.
 */
static gint columns_focus(FOCUS_METHOD_SUPERCLASS *super, GtkDirectionType dir)
{
    Columns *cols;
    GList *pos;
    GtkWidget *focuschild;

    g_return_val_if_fail(super != NULL, false);
    g_return_val_if_fail(IS_COLUMNS(super), false);

    cols = COLUMNS(super);

    if (!gtk_widget_is_drawable(GTK_WIDGET(cols)) ||
        !gtk_widget_is_sensitive(GTK_WIDGET(cols)))
        return false;

    if (!gtk_widget_get_can_focus(GTK_WIDGET(cols)) &&
        (dir == GTK_DIR_TAB_FORWARD || dir == GTK_DIR_TAB_BACKWARD)) {

        focuschild = gtk_container_get_focus_child(GTK_CONTAINER(cols));
        gtk_container_set_focus_child(GTK_CONTAINER(cols), NULL);

        if (dir == GTK_DIR_TAB_FORWARD)
            pos = cols->taborder;
        else
            pos = g_list_last(cols->taborder);

        while (pos) {
            GtkWidget *child = pos->data;

            if (focuschild) {
                if (focuschild == child) {
                    focuschild = NULL; /* now we can start looking in here */
                    if (gtk_widget_is_drawable(child) &&
                        GTK_IS_CONTAINER(child) &&
                        !gtk_widget_has_focus(child)) {
                        if (CHILD_FOCUS(child, dir))
                            return true;
                    }
                }
            } else if (gtk_widget_is_drawable(child)) {
                if (GTK_IS_CONTAINER(child)) {
                    if (CHILD_FOCUS(child, dir))
                        return true;
                } else if (gtk_widget_get_can_focus(child)) {
                    gtk_widget_grab_focus(child);
                    return true;
                }
            }

            if (dir == GTK_DIR_TAB_FORWARD)
                pos = pos->next;
            else
                pos = pos->prev;
        }

        return false;
    } else
        return columns_inherited_focus(super, dir);
}

/*
 * Underlying parts of the layout algorithm, to compute the Columns
 * container's width or height given the widths or heights of its
 * children. These will be called in various ways with different
 * notions of width and height in use, so we abstract them out and
 * pass them a 'get width' or 'get height' function pointer.
 */

typedef gint (*widget_dim_fn_t)(ColumnsChild *child);

static gint columns_compute_width(Columns *cols, widget_dim_fn_t get_width)
{
    ColumnsChild *child;
    GList *children;
    gint i, ncols, colspan, retwidth, childwidth;
    const gint *percentages;
    static const gint onecol[] = { 100 };

#ifdef COLUMNS_WIDTH_DIAGNOSTICS
    printf("compute_width(%p): start\n", cols);
#endif

    retwidth = 0;

    ncols = 1;
    percentages = onecol;

    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {

        if (!child->widget) {
            /* Column reconfiguration. */
            ncols = child->ncols;
            percentages = child->percentages;
            continue;
        }

        /* Only take visible widgets into account. */
        if (!gtk_widget_get_visible(child->widget))
            continue;

        childwidth = get_width(child);
        colspan = child->colspan ? child->colspan : ncols-child->colstart;
        assert(colspan > 0);

#ifdef COLUMNS_WIDTH_DIAGNOSTICS
        printf("compute_width(%p): ", cols);
        if (GTK_IS_LABEL(child->widget))
            printf("label %p '%s' wrap=%s: ", child->widget,
                   gtk_label_get_text(GTK_LABEL(child->widget)),
                   (gtk_label_get_line_wrap(GTK_LABEL(child->widget))
                    ? "true" : "false"));
        else
            printf("widget %p: ", child->widget);
        {
            gint min, nat;
            gtk_widget_get_preferred_width(child->widget, &min, &nat);
            printf("minwidth=%d natwidth=%d ", min, nat);
        }
        printf("thiswidth=%d span=%d\n", childwidth, colspan);
#endif

        /*
         * To compute width: we know that childwidth + cols->spacing
         * needs to equal a certain percentage of the full width of
         * the container. So we work this value out, figure out how
         * wide the container will need to be to make that percentage
         * of it equal to that width, and ensure our returned width is
         * at least that much. Very simple really.
         */
        {
            int percent, thiswid, fullwid;

            percent = 0;
            for (i = 0; i < colspan; i++)
                percent += percentages[child->colstart+i];

            thiswid = childwidth + cols->spacing;
            /*
             * Since childwidth is (at least sometimes) the _minimum_
             * size the child needs, we must ensure that it gets _at
             * least_ that size. Hence, when scaling thiswid up to
             * fullwid, we must round up, which means adding percent-1
             * before dividing by percent.
             */
            fullwid = (thiswid * 100 + percent - 1) / percent;
#ifdef COLUMNS_WIDTH_DIAGNOSTICS
            printf("compute_width(%p): after %p, thiswid=%d fullwid=%d\n",
                   cols, child->widget, thiswid, fullwid);
#endif

            /*
             * The above calculation assumes every widget gets
             * cols->spacing on the right. So we subtract
             * cols->spacing here to account for the extra load of
             * spacing on the right.
             */
            if (retwidth < fullwid - cols->spacing)
                retwidth = fullwid - cols->spacing;
        }
    }

    retwidth += 2*gtk_container_get_border_width(GTK_CONTAINER(cols));

#ifdef COLUMNS_WIDTH_DIAGNOSTICS
    printf("compute_width(%p): done, returning %d\n", cols, retwidth);
#endif

    return retwidth;
}

static void columns_alloc_horiz(Columns *cols, gint ourwidth,
                                widget_dim_fn_t get_width)
{
    ColumnsChild *child;
    GList *children;
    gint i, ncols, colspan, border, *colxpos, childwidth;

    border = gtk_container_get_border_width(GTK_CONTAINER(cols));

    ncols = 1;
    /* colxpos gives the starting x position of each column.
     * We supply n+1 of them, so that we can find the RH edge easily.
     * All ending x positions are expected to be adjusted afterwards by
     * subtracting the spacing. */
    colxpos = g_new(gint, 2);
    colxpos[0] = 0;
    colxpos[1] = ourwidth - 2*border + cols->spacing;

    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {

        if (!child->widget) {
            gint percent;

            /* Column reconfiguration. */
            ncols = child->ncols;
            colxpos = g_renew(gint, colxpos, ncols + 1);
            colxpos[0] = 0;
            percent = 0;
            for (i = 0; i < ncols; i++) {
                percent += child->percentages[i];
                colxpos[i+1] = (((ourwidth - 2*border) + cols->spacing)
                                * percent / 100);
            }
            continue;
        }

        /* Only take visible widgets into account. */
        if (!gtk_widget_get_visible(child->widget))
            continue;

        childwidth = get_width(child);
        colspan = child->colspan ? child->colspan : ncols-child->colstart;

        /*
         * Starting x position is cols[colstart].
         * Ending x position is cols[colstart+colspan] - spacing.
         *
         * Unless we're forcing left, in which case the width is
         * exactly the requisition width.
         */
        child->x = colxpos[child->colstart];
        if (child->force_left)
            child->w = childwidth;
        else
            child->w = (colxpos[child->colstart+colspan] -
                        colxpos[child->colstart] - cols->spacing);
    }

    g_free(colxpos);
}

static gint columns_compute_height(Columns *cols, widget_dim_fn_t get_height)
{
    ColumnsChild *child;
    GList *children;
    gint i, ncols, colspan, *colypos, retheight, childheight;

    retheight = cols->spacing;

    ncols = 1;
    colypos = g_new(gint, 1);
    colypos[0] = 0;

    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {

        if (!child->widget) {
            /* Column reconfiguration. */
            for (i = 1; i < ncols; i++) {
                if (colypos[0] < colypos[i])
                    colypos[0] = colypos[i];
            }
            ncols = child->ncols;
            colypos = g_renew(gint, colypos, ncols);
            for (i = 1; i < ncols; i++)
                colypos[i] = colypos[0];
            continue;
        }

        /* Only take visible widgets into account. */
        if (!gtk_widget_get_visible(child->widget))
            continue;

        childheight = get_height(child);
        for (ColumnsChild *ch = child->valign_next; ch != child;
             ch = ch->valign_next) {
            gint childheight2 = get_height(ch);
            if (childheight < childheight2)
                childheight = childheight2;
        }
        colspan = child->colspan ? child->colspan : ncols-child->colstart;

        /*
         * To compute height: the widget's top will be positioned at
         * the largest y value so far reached in any of the columns it
         * crosses. Then it will go down by childheight plus padding;
         * and the point it reaches at the bottom is the new y value
         * in all those columns, and minus the padding it is also a
         * lower bound on our own height.
         */
        {
            int topy, boty;

            topy = 0;
            for (i = 0; i < colspan; i++) {
                if (topy < colypos[child->colstart+i])
                    topy = colypos[child->colstart+i];
            }
            boty = topy + childheight + cols->spacing;
            for (i = 0; i < colspan; i++) {
                colypos[child->colstart+i] = boty;
            }

            if (retheight < boty - cols->spacing)
                retheight = boty - cols->spacing;
        }
    }

    retheight += 2*gtk_container_get_border_width(GTK_CONTAINER(cols));

    g_free(colypos);

    return retheight;
}

static void columns_alloc_vert(Columns *cols, gint ourheight,
                               widget_dim_fn_t get_height)
{
    ColumnsChild *child;
    GList *children;
    gint i, ncols, colspan, *colypos, realheight, fakeheight, vexpand_extra;

    if (cols->vexpand) {
        gint minheight = columns_compute_height(cols, get_height);
        vexpand_extra = ourheight - minheight;
    } else {
        vexpand_extra = 0;
    }

    ncols = 1;
    /* As in size_request, colypos is the lowest y reached in each column. */
    colypos = g_new(gint, 1);
    colypos[0] = 0;

    for (children = cols->children;
         children && (child = children->data);
         children = children->next)
        child->visited = false;

    /*
     * Main layout loop. In this loop, vertically aligned controls are
     * only half dealt with: we assign each one enough _height_ to
     * match the others in its group, but we don't adjust its y
     * coordinates yet.
     */
    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {
        if (!child->widget) {
            /* Column reconfiguration. */
            for (i = 1; i < ncols; i++) {
                if (colypos[0] < colypos[i])
                    colypos[0] = colypos[i];
            }
            ncols = child->ncols;
            colypos = g_renew(gint, colypos, ncols);
            for (i = 1; i < ncols; i++)
                colypos[i] = colypos[0];
            continue;
        }

        /* Only take visible widgets into account. */
        if (!gtk_widget_get_visible(child->widget))
            continue;

        int ymin = 0;

        realheight = get_height(child);
        if (child == cols->vexpand)
            realheight += vexpand_extra;
        fakeheight = realheight;
        for (ColumnsChild *ch = child->valign_next; ch != child;
             ch = ch->valign_next) {
            gint childheight2 = get_height(ch);
            if (fakeheight < childheight2)
                fakeheight = childheight2;
            if (ch->visited && ymin < ch->y)
                ymin = ch->y;
        }
        colspan = child->colspan ? child->colspan : ncols-child->colstart;

        /*
         * To compute height: the widget's top will be positioned
         * at the largest y value so far reached in any of the
         * columns it crosses. Then it will go down by creq.height
         * plus padding; and the point it reaches at the bottom is
         * the new y value in all those columns.
         */
        {
            int topy, boty;

            topy = ymin;
            for (i = 0; i < colspan; i++) {
                if (topy < colypos[child->colstart+i])
                    topy = colypos[child->colstart+i];
            }
            child->y = topy;
            child->h = realheight;
            child->visited = true;
            boty = topy + fakeheight + cols->spacing;
            for (i = 0; i < colspan; i++) {
                colypos[child->colstart+i] = boty;
            }
        }
    }

    /*
     * Now make a separate pass that deals with vertical alignment by
     * moving controls downwards based on the difference between their
     * own height and the largest height of anything in their group.
     */
    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {
        if (!child->widget)
            continue;
        if (!gtk_widget_get_visible(child->widget))
            continue;

        fakeheight = realheight = child->h;
        for (ColumnsChild *ch = child->valign_next; ch != child;
             ch = ch->valign_next) {
            if (fakeheight < ch->h)
                fakeheight = ch->h;
        }
        child->y += fakeheight/2 - realheight/2;
    }

    g_free(colypos);
}

/*
 * Now here comes the interesting bit. The actual layout part is
 * done in the following two functions:
 *
 * columns_size_request() examines the list of widgets held in the
 * Columns, and returns a requisition stating the absolute minimum
 * size it can bear to be.
 *
 * columns_size_allocate() is given an allocation telling it what
 * size the whole container is going to be, and it calls
 * gtk_widget_size_allocate() on all of its (visible) children to
 * set their size and position relative to the top left of the
 * container.
 */

#if !GTK_CHECK_VERSION(3,0,0)

static gint columns_gtk2_get_width(ColumnsChild *child)
{
    GtkRequisition creq;
    gtk_widget_size_request(child->widget, &creq);
    return creq.width;
}

static gint columns_gtk2_get_height(ColumnsChild *child)
{
    GtkRequisition creq;
    gtk_widget_size_request(child->widget, &creq);
    return creq.height;
}

static void columns_size_request(GtkWidget *widget, GtkRequisition *req)
{
    Columns *cols;

    g_return_if_fail(widget != NULL);
    g_return_if_fail(IS_COLUMNS(widget));
    g_return_if_fail(req != NULL);

    cols = COLUMNS(widget);

    req->width = columns_compute_width(cols, columns_gtk2_get_width);
    req->height = columns_compute_height(cols, columns_gtk2_get_height);
}

static void columns_size_allocate(GtkWidget *widget, GtkAllocation *alloc)
{
    Columns *cols;
    ColumnsChild *child;
    GList *children;
    gint border;

    g_return_if_fail(widget != NULL);
    g_return_if_fail(IS_COLUMNS(widget));
    g_return_if_fail(alloc != NULL);

    cols = COLUMNS(widget);
    gtk_widget_set_allocation(widget, alloc);

    border = gtk_container_get_border_width(GTK_CONTAINER(cols));

    columns_alloc_horiz(cols, alloc->width, columns_gtk2_get_width);
    columns_alloc_vert(cols, alloc->height, columns_gtk2_get_height);

    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {
        if (child->widget && gtk_widget_get_visible(child->widget)) {
            GtkAllocation call;
            call.x = alloc->x + border + child->x;
            call.y = alloc->y + border + child->y;
            call.width = child->w;
            call.height = child->h;
            gtk_widget_size_allocate(child->widget, &call);
        }
    }
}

#else /* GTK_CHECK_VERSION(3,0,0) */

static gint columns_gtk3_get_min_width(ColumnsChild *child)
{
    gint ret;
    gtk_widget_get_preferred_width(child->widget, &ret, NULL);
    return ret;
}

static gint columns_gtk3_get_nat_width(ColumnsChild *child)
{
    gint ret;

    if ((GTK_IS_LABEL(child->widget) &&
         gtk_label_get_line_wrap(GTK_LABEL(child->widget))) ||
        GTK_IS_ENTRY(child->widget)) {
        /*
         * We treat wrapping GtkLabels as a special case in this
         * layout class, because the whole point of those is that I
         * _don't_ want them to take up extra horizontal space for
         * long text, but instead to wrap it to whatever size is used
         * by the rest of the layout.
         *
         * GtkEntry gets similar treatment, because in OS X GTK I've
         * found that it requests a natural width regardless of the
         * output of gtk_entry_set_width_chars.
         */
        gtk_widget_get_preferred_width(child->widget, &ret, NULL);
    } else {
        gtk_widget_get_preferred_width(child->widget, NULL, &ret);
    }
    return ret;
}

static gint columns_gtk3_get_minfh_width(ColumnsChild *child)
{
    gint ret;
    gtk_widget_get_preferred_width_for_height(child->widget, child->h,
                                              &ret, NULL);
    return ret;
}

static gint columns_gtk3_get_natfh_width(ColumnsChild *child)
{
    gint ret;
    gtk_widget_get_preferred_width_for_height(child->widget, child->h,
                                              NULL, &ret);
    return ret;
}

static gint columns_gtk3_get_min_height(ColumnsChild *child)
{
    gint ret;
    gtk_widget_get_preferred_height(child->widget, &ret, NULL);
    return ret;
}

static gint columns_gtk3_get_nat_height(ColumnsChild *child)
{
    gint ret;
    gtk_widget_get_preferred_height(child->widget, NULL, &ret);
    return ret;
}

static gint columns_gtk3_get_minfw_height(ColumnsChild *child)
{
    gint ret;
    gtk_widget_get_preferred_height_for_width(child->widget, child->w,
                                              &ret, NULL);
    return ret;
}

static gint columns_gtk3_get_natfw_height(ColumnsChild *child)
{
    gint ret;
    gtk_widget_get_preferred_height_for_width(child->widget, child->w,
                                              NULL, &ret);
    return ret;
}

static void columns_get_preferred_width(GtkWidget *widget,
                                        gint *min, gint *nat)
{
    Columns *cols;

    g_return_if_fail(widget != NULL);
    g_return_if_fail(IS_COLUMNS(widget));

    cols = COLUMNS(widget);

    if (min)
        *min = columns_compute_width(cols, columns_gtk3_get_min_width);
    if (nat)
        *nat = columns_compute_width(cols, columns_gtk3_get_nat_width);
}

static void columns_get_preferred_height(GtkWidget *widget,
                                         gint *min, gint *nat)
{
    Columns *cols;

    g_return_if_fail(widget != NULL);
    g_return_if_fail(IS_COLUMNS(widget));

    cols = COLUMNS(widget);

    if (min)
        *min = columns_compute_height(cols, columns_gtk3_get_min_height);
    if (nat)
        *nat = columns_compute_height(cols, columns_gtk3_get_nat_height);
}

static void columns_get_preferred_width_for_height(GtkWidget *widget,
                                                   gint height,
                                                   gint *min, gint *nat)
{
    Columns *cols;

    g_return_if_fail(widget != NULL);
    g_return_if_fail(IS_COLUMNS(widget));

    cols = COLUMNS(widget);

    /* FIXME: which one should the get-height function here be? */
    columns_alloc_vert(cols, height, columns_gtk3_get_nat_height);

    if (min)
        *min = columns_compute_width(cols, columns_gtk3_get_minfh_width);
    if (nat)
        *nat = columns_compute_width(cols, columns_gtk3_get_natfh_width);
}

static void columns_get_preferred_height_for_width(GtkWidget *widget,
                                                   gint width,
                                                   gint *min, gint *nat)
{
    Columns *cols;

    g_return_if_fail(widget != NULL);
    g_return_if_fail(IS_COLUMNS(widget));

    cols = COLUMNS(widget);

    /* FIXME: which one should the get-height function here be? */
    columns_alloc_horiz(cols, width, columns_gtk3_get_nat_width);

    if (min)
        *min = columns_compute_height(cols, columns_gtk3_get_minfw_height);
    if (nat)
        *nat = columns_compute_height(cols, columns_gtk3_get_natfw_height);
}

static void columns_size_allocate(GtkWidget *widget, GtkAllocation *alloc)
{
    Columns *cols;
    ColumnsChild *child;
    GList *children;
    gint border;

    g_return_if_fail(widget != NULL);
    g_return_if_fail(IS_COLUMNS(widget));
    g_return_if_fail(alloc != NULL);

    cols = COLUMNS(widget);
    gtk_widget_set_allocation(widget, alloc);

    border = gtk_container_get_border_width(GTK_CONTAINER(cols));

    columns_alloc_horiz(cols, alloc->width, columns_gtk3_get_min_width);
    columns_alloc_vert(cols, alloc->height, columns_gtk3_get_minfw_height);

    for (children = cols->children;
         children && (child = children->data);
         children = children->next) {
        if (child->widget && gtk_widget_get_visible(child->widget)) {
            GtkAllocation call;
            call.x = alloc->x + border + child->x;
            call.y = alloc->y + border + child->y;
            call.width = child->w;
            call.height = child->h;
            gtk_widget_size_allocate(child->widget, &call);
        }
    }
}

#endif
