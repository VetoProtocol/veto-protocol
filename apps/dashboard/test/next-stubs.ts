/** Minimal stand-ins so server modules can be imported under vitest. */
export const revalidatePath = (): void => {};
export const cookies = async () => ({ get: () => undefined });
export default {};
