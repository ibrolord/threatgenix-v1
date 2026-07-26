import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import IntakeForm from "./IntakeForm";

const { createThreatModel } = vi.hoisted(() => ({
  createThreatModel: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: {
    createThreatModel,
  },
}));

describe("IntakeForm", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("blocks overlong architecture summaries before they hit the backend", async () => {
    const user = userEvent.setup();

    render(<IntakeForm onSuccess={vi.fn()} />);

    await user.type(screen.getByLabelText("Application or PR Name"), "Northstar Banking Mesh");
    fireEvent.change(screen.getByLabelText("Review Summary"), {
      target: { value: "x".repeat(501) },
    });
    await user.click(screen.getByRole("button", { name: "Start Security Review" }));

    expect(
      await screen.findByText(/Review summary must be 500 characters or fewer/i),
    ).toBeInTheDocument();
    expect(createThreatModel).not.toHaveBeenCalled();
  });
});
