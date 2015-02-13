#!/usr/bin/env python


class InternalLink(object):
    """A link controller for two endpoints in the same process."""
    def __init__(self, physics_A, physics_B):

        self.physics_A = physics_A
        self.physics_B = physics_B
        self.messages = []

    def run_proto(self):
        """Run a single iteration of the protocol."""

        self.physics_A.reset()
        self.physics_B.reset()

        self.messages = []

        self.messages.append(self.physics_A.exchange(0.0))

        for i in range(self.physics_A.number_of_exchanges):
            self.messages.append(self.physics_B.exchange(self.messages[-1]))
            self.messages.append(self.physics_A.exchange(self.messages[-1]))

        if not (self.physics_A.estimate_other()
                    ^ (self.physics_A.reflection_coefficient > 0)):
            return None

        elif not (self.physics_B.estimate_other()
                    ^ (self.physics_B.reflection_coefficient > 0)):
            return None

        else:
            return (not self.physics_A.estimate_other(),
                    self.physics_B.estimate_other())