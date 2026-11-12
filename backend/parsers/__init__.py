from .base import BaseParser
from .client.mattermost import MattermostClientParser
from .client.rocketchat import RocketChatClientParser
from .client.zulip import ZulipClientParser
from .server.mattermost import MattermostServerParser
from .server.rocketchat import RocketChatServerParser
from .server.zulip import ZulipServerParser

PARSERS: dict[tuple[str, str], type[BaseParser]] = {
    (p.mode, p.app): p
    for p in (
        MattermostClientParser, ZulipClientParser, RocketChatClientParser,
        MattermostServerParser, ZulipServerParser, RocketChatServerParser,
    )
}


def get_parser(mode: str, app: str) -> BaseParser:
    return PARSERS[(mode, app)]()
