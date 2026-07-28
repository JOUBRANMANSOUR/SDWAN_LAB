from sdwan_v4.common.marks import FlowMarkStage, MarkLayout


def test_terminal_does_not_mean_identified() -> None:
    layout = MarkLayout()
    mark = layout.encode(2, FlowMarkStage.TERMINAL)
    assert mark == 0x102
    assert layout.path_value(mark) == 2
    assert layout.stage(mark) is FlowMarkStage.TERMINAL


def test_fields_do_not_overlap() -> None:
    MarkLayout().validate({"mpls": 1, "bb": 2, "lte": 3})
